import { afterEach, expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import {
  AppleSharing,
  assertAppleAccess,
  resolveAppleAccess,
} from '../packages/core/src/apple/access';
import { DeviceOnboarding, profileServiceXml } from '../packages/core/src/devices/onboarding';
import { JobsActions } from '../packages/core/src/signing/jobs-actions';
import { hash } from '../packages/core/src/shared/index';
import { Service } from '../packages/core/src/application/service';
import { Publisher, digest, type VerifiedReport } from '../packages/core/src/signing/publisher';
import { Tickets } from '../packages/core/src/library/tickets';
import { Vault } from '../packages/core/src/apple/vault';
import { PipelineCoordinator, type AnalysisVm } from '../packages/core/src/signing/pipeline';
import { MappingService } from '../packages/core/src/signing/mapping';
import { Readable } from 'node:stream';
const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
});
async function harness() {
  const db = await createDatabase();
  closers.push(() => db.close());
  for (const user of ['owner', 'recipient', 'other'])
    await db.query('INSERT INTO users(id,login_name,created_at) VALUES($1,$2,0)', [
      user,
      user + '@synthetic.invalid',
    ]);
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('connection','owner','ABCDEFGHIJ','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('owner','connection','owner')",
  );
  const sharing = new AppleSharing(db, () => 100),
    publicId = (
      await db.query<{ public_profile_id: string }>(
        "SELECT public_profile_id FROM users WHERE id='recipient'",
      )
    ).rows[0].public_profile_id;
  const { grantId } = await sharing.share('owner', publicId);
  const offered = { id: grantId, generation: 1 };
  return { db, sharing, offered, publicId };
}
async function accepted() {
  const h = await harness();

  return h;
}
async function enrolled(
  h: Awaited<ReturnType<typeof accepted>>,
  api = {
    find: async () => [{ id: 'apple-device', status: 'ENABLED', eligible: true }],
    register: async () => ({ id: 'apple-device', status: 'ENABLED', eligible: true }),
  },
) {
  let challenge = '';
  const devices = new DeviceOnboarding(
    h.db,
    api,
    () => 100,
    async () => ({
      challenge,
      udid: 'A'.repeat(40),
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    }),
  );
  challenge = (await devices.challenge('recipient', 'connection')).challenge;
  const result = await devices.callback(challenge, Buffer.from('SYNTHETIC TRUSTED CMS PAYLOAD'));
  await devices.reportOs('recipient', result.id, '18.0');
  await devices.register('recipient', result.id, true);
  return { devices, device: result.id };
}
async function upload(h: Awaited<ReturnType<typeof accepted>>) {
  await h.db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('upload','recipient','Synthetic.ipa','synthetic-object',6,$1,'uploaded',0,999999)",
    [hash('source')],
  );
}
it('public profile ID is a lookup, only an owner may share or revoke', async () => {
  const h = await harness();
  expect(h.publicId).toMatch(/^profile_[a-f0-9]{32}$/);
  const access = await resolveAppleAccess(h.db, 'recipient', 'connection', 1);
  expect(access.connectionOwnerId).toBe('owner');
  expect(access.accessGrantId).toBe(h.offered.id);
  await expect(h.sharing.share('recipient', h.publicId)).rejects.toThrow('CONNECTION_UNAVAILABLE');
  await expect(h.sharing.revoke('recipient', h.offered.id)).rejects.toThrow('SHARE_NOT_FOUND');
  await h.sharing.revoke('owner', h.offered.id);
  await expect(assertAppleAccess(h.db, access)).rejects.toThrow('APPLE_ACCESS_UNAVAILABLE');
});
it('mandatory minimal profile cannot be replaced by manual/foreign provenance or revoked nonce', async () => {
  const h = await accepted();
  const { devices, device } = await enrolled(h);
  const profile = profileServiceXml('https://synthetic.invalid', 'a'.repeat(43));
  const attributes = profile.match(/<key>DeviceAttributes<\/key><array>(.*?)<\/array>/)?.[1] ?? '';
  expect([...attributes.matchAll(/<string>(.*?)<\/string>/g)].map((match) => match[1])).toEqual([
    'UDID',
    'PRODUCT',
    'VERSION',
  ]);
  expect(profile).not.toMatch(/<string>(SERIAL|IMEI)<\/string>|MDM|SCEP/);
  await expect(devices.register('other', device, true)).rejects.toThrow('DEVICE_NOT_FOUND');
  const challenge = await devices.challenge('recipient', 'connection');
  await h.sharing.revoke('owner', h.offered.id);
  await expect(devices.callback(challenge.challenge, Buffer.from('synthetic'))).rejects.toThrow();
  expect((await h.db.query('SELECT id FROM signing_devices')).rows).toHaveLength(0);
});
it('registration timeout and concurrent retries use durable GET reconciliation with one POST', async () => {
  const h = await accepted();
  let posts = 0,
    exists = false,
    current = '';
  const devices = new DeviceOnboarding(
    h.db,
    {
      find: async () => (exists ? [{ id: 'apple-device', status: 'ENABLED', eligible: true }] : []),
      register: async () => {
        posts++;
        exists = true;
        throw Error('synthetic remote timeout');
      },
    },
    () => 100,
    async () => ({
      challenge: current,
      udid: 'B'.repeat(40),
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    }),
  );
  current = (await devices.challenge('recipient', 'connection')).challenge;
  const device = await devices.callback(current, Buffer.from('trusted synthetic CMS'));
  await expect(devices.register('recipient', device.id, true)).rejects.toThrow(
    'synthetic remote timeout',
  );
  expect(posts).toBe(1);
  expect(
    (await h.db.query<{ state: string }>('SELECT state FROM device_registration_operations'))
      .rows[0].state,
  ).toBe('unknown');
  await devices.register('recipient', device.id, true);
  expect(posts).toBe(1);
  expect(
    (await h.db.query<{ state: string }>('SELECT state FROM device_registration_operations'))
      .rows[0].state,
  ).toBe('complete');
});
it('revoke after POST keeps result evidence, fences final readiness, never deletes the Apple device', async () => {
  const h = await accepted();
  let current = '',
    posts = 0;
  const devices = new DeviceOnboarding(
    h.db,
    {
      find: async () => [],
      register: async () => {
        posts++;
        await h.sharing.revoke('owner', h.offered.id);
        return { id: 'apple-device', status: 'ENABLED', eligible: true };
      },
    },
    () => 100,
    async () => ({
      challenge: current,
      udid: 'C'.repeat(40),
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    }),
  );
  current = (await devices.challenge('recipient', 'connection')).challenge;
  const device = await devices.callback(current, Buffer.from('synthetic'));
  await expect(devices.register('recipient', device.id, true)).rejects.toThrow(
    'CONNECTION_CHANGED',
  );
  expect(posts).toBe(1);
  expect(
    (
      await h.db.query<{ state: string; resource_id: string }>(
        'SELECT state,resource_id FROM device_registration_operations',
      )
    ).rows[0],
  ).toEqual({ state: 'revoked', resource_id: 'apple-device' });
});
for (const revokeAt of ['none', 'unwrap', 'publication'] as const)
  it(
    'split-owner encrypted material, publisher and OTA admission synthetic ' + revokeAt,
    async () => {
      const h = await accepted();
      const { device } = await enrolled(h);
      await upload(h);
      const actions = new JobsActions(
        h.db,
        () => 100,
        async () => {},
      );
      const job = await actions.ensure('recipient', {
        uploadId: 'upload',
        deviceId: device,
        key: 'synthetic',
      });
      await h.db.query(
        "UPDATE jobs SET state='provisioning',lease_token='lease',lease_expires=999999 WHERE id=$1",
        [job.id],
      );
      let dataKey: Buffer | undefined;
      const kms = {
        generate: async () => ({ plaintext: Buffer.alloc(32, 7), wrapped: 'synthetic-kms-key' }),
        unwrap: async () => {
          dataKey = Buffer.alloc(32, 7);
          if (revokeAt === 'unwrap') await h.sharing.revoke('owner', h.offered.id);
          return dataKey;
        },
      };
      const vault = new Vault(h.db, kms, () => 100);
      const secret = await vault.seal(
        'owner',
        'connection',
        'distribution-key',
        Buffer.from('SYNTHETIC ENCRYPTED PEM PACKAGE'),
      );
      const bytes = Buffer.from('SYNTHETIC ARTIFACT — not a signed IPA');
      let deleted = false;
      const publisher = new Publisher(
        h.db,
        {
          put: async () => {
            if (revokeAt === 'publication') await h.sharing.revoke('owner', h.offered.id);
            return { digest: digest(bytes), size: bytes.length };
          },
          delete: async () => {
            deleted = true;
          },
        },
        { verify: async () => true },
        () => 100,
      );
      const grant = await publisher.grant(
        'recipient',
        job.id,
        'lease',
        'synthetic-vm',
        'a'.repeat(64),
      );
      expect(grant).toMatchObject({
        ownerId: 'recipient',
        connectionOwnerId: 'owner',
        accessGrantId: h.offered.id,
        accessGrantGeneration: 1,
      });
      if (revokeAt === 'unwrap') {
        await expect(vault.prepareJobMaterial(grant, secret)).rejects.toThrow('SECRET_UNAVAILABLE');
        expect(dataKey?.equals(Buffer.alloc(32))).toBe(true);
        return;
      }
      const issued = await vault.prepareJobMaterial(grant, secret);
      expect(issued.envelope.owner).toBe('owner');
      expect(JSON.parse(issued.envelope.aad).owner).toBe('owner');
      issued.dataKey.fill(0);
      await expect(vault.openForConnection('recipient', 'connection', 1)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      const report: VerifiedReport = {
        ...grant,
        artifactDigest: digest(bytes),
        bundleId: 'test.synthetic',
        version: '1',
        title: 'Synthetic fixture',
        certificateExpiresAt: 999999,
        profileExpiresAt: 999999,
        checks: {
          archive: true,
          components: true,
          signatures: true,
          profiles: true,
          device: true,
          entitlements: true,
          mapping: true,
        },
      };
      if (revokeAt === 'publication') {
        await expect(
          publisher.publish(report, 'SYNTHETIC ATTESTATION', Readable.from([bytes])),
        ).rejects.toThrow();
        expect(deleted).toBe(true);
        expect((await h.db.query('SELECT id FROM artifacts')).rows).toHaveLength(0);
        return;
      }
      const artifact = await publisher.publish(
        report,
        'SYNTHETIC ATTESTATION',
        Readable.from([bytes]),
      );
      expect(
        (
          await h.db.query<{ owner_id: string; connection_owner_id: string }>(
            'SELECT owner_id,connection_owner_id FROM artifacts',
          )
        ).rows[0],
      ).toEqual({ owner_id: 'recipient', connection_owner_id: 'owner' });
      const tickets = new Tickets(h.db, () => 100);
      await expect(tickets.issue('owner', artifact.id)).rejects.toThrow('NOT_FOUND');
      const handoff = await tickets.issue('recipient', artifact.id),
        ticket = await tickets.issue('recipient', artifact.id);
      await h.sharing.revoke('owner', h.offered.id);
      await expect(tickets.resolve(handoff)).rejects.toThrow('NOT_FOUND');
      await expect(tickets.resolve(ticket)).rejects.toThrow('NOT_FOUND');
      expect((await h.db.query('SELECT owner_id FROM uploads')).rows[0]).toEqual({
        owner_id: 'recipient',
      });
    },
  );
it('full PipelineCoordinator synthetic recipient signing keeps recipient-owned data and actual owner binding', async () => {
  const h = await accepted();
  const { device } = await enrolled(h);
  await upload(h);
  const service = new Service(h.db, { now: () => 100 }),
    actions = new JobsActions(
      h.db,
      () => 100,
      async () => {},
    ),
    job = await actions.ensure('recipient', {
      uploadId: 'upload',
      deviceId: device,
      key: 'pipeline',
    });
  const bytes = Buffer.from('SYNTHETIC PIPELINE ARTIFACT'),
    publisher = new Publisher(
      h.db,
      { put: async () => ({ digest: digest(bytes), size: bytes.length }), delete: async () => {} },
      { verify: async () => true },
      () => 100,
    );
  const components = [
    {
      kind: 'app' as const,
      path: 'Payload/Synthetic.app',
      bundleId: 'test.synthetic',
      platform: 'ios',
      architectures: ['arm64'],
      encrypted: false,
      entitlements: {},
      minOs: '17.0',
    },
  ];
  let destroyed = false;
  const vm: AnalysisVm = {
    id: 'synthetic-vm',
    expiresAt: 999999,
    destroy: async () => {
      destroyed = true;
    },
    analyze: async ({ grant }) => ({
      report: {
        ...grant,
        protocolVersion: 1,
        operation: 'analysis',
        executionAuthorized: false,
        analysis: {
          sha256: grant.uploadDigest,
          bundleId: 'test.synthetic',
          version: '1',
          title: 'Synthetic',
          components,
        },
      },
      attestation: 'SYNTHETIC',
    }),
    execute: async ({ grant }) => ({
      report: {
        ...grant,
        artifactDigest: digest(bytes),
        bundleId: 'test.synthetic',
        version: '1',
        title: 'Synthetic',
        certificateExpiresAt: 999999,
        profileExpiresAt: 999999,
        checks: {
          archive: true,
          components: true,
          signatures: true,
          profiles: true,
          device: true,
          entitlements: true,
          mapping: true,
        },
      },
      attestation: 'SYNTHETIC',
      body: Readable.from([bytes]),
    }),
  };
  const pipeline = new PipelineCoordinator({
    db: h.db,
    service,
    publisher,
    mapping: new MappingService(h.db),
    now: () => 100,
    provider: { launch: async () => vm, verifyInstance: async () => true },
    attestor: { verify: async () => true },
    storage: {
      read: async () => ({
        stat: async () => ({ size: 6 }),
        createReadStream: () => Readable.from([Buffer.from('source')]),
        close: async () => {},
      }),
      upload: async () => {
        throw Error('unused');
      },
      cleanup: async () => {},
      recoverInterrupted: async () => {},
    },
    canPreserve: async () => true,
    provision: async ({ grant }) => {
      expect(grant.connectionOwnerId).toBe('owner');
      const identity = {
        ownerId: 'recipient',
        teamId: 'ABCDEFGHIJ',
        prefix: 'ABCDEFGHIJ',
        fingerprint: 'A'.repeat(40),
        expiresAt: 999999,
        materialPath: 'materials/key.p12',
      };
      return {
        identity,
        profiles: {
          'test.synthetic': {
            ...identity,
            bundleId: 'test.synthetic',
            udids: ['A'.repeat(40)],
            entitlements: {
              'application-identifier': 'ABCDEFGHIJ.test.synthetic',
              'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
              'get-task-allow': false,
            },
            materialPath: 'materials/profile.mobileprovision',
          },
        },
        udid: 'A'.repeat(40),
        deviceOs: '18.0',
      };
    },
  });
  await pipeline.kickoff('recipient', job.id, device);
  expect(destroyed).toBe(true);
  expect(
    (await h.db.query<{ owner_id: string; state: string }>('SELECT owner_id,state FROM jobs'))
      .rows[0],
  ).toEqual({ owner_id: 'recipient', state: 'ready' });
  expect((await h.db.query('SELECT owner_id FROM mappings')).rows[0]).toEqual({
    owner_id: 'recipient',
  });
});
it('Apple ENABLED freshness gates ticket admission and expired grant snapshots cannot revive after reaccept', async () => {
  const h = await accepted();
  let enabled = true,
    current = '';
  const devices = new DeviceOnboarding(
    h.db,
    {
      find: async () => [{ id: 'apple-device', status: 'ENABLED', eligible: true }],
      register: async () => ({ id: 'apple-device', status: 'ENABLED', eligible: true }),
      rawDevice: async (udid, resource) => {
        expect(udid).toBe('D'.repeat(40));
        expect(resource).toBe('apple-device');
        return { id: resource, status: enabled ? 'ENABLED' : 'DISABLED' };
      },
    },
    () => 100,
    async () => ({
      challenge: current,
      udid: 'D'.repeat(40),
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    }),
  );
  current = (await devices.challenge('recipient', 'connection')).challenge;
  const d = await devices.callback(current, Buffer.from('synthetic trusted CMS'));
  await devices.reportOs('recipient', d.id, '18.0');
  await devices.register('recipient', d.id, true);
  await upload(h);
  const job = await new JobsActions(
    h.db,
    () => 100,
    async () => {},
  ).ensure('recipient', { uploadId: 'upload', deviceId: d.id, key: 'freshness' });
  await h.db.query("UPDATE jobs SET state='ready' WHERE id=$1", [job.id]);
  await h.db.query(
    "INSERT INTO artifacts(id,owner_id,job_id,connection_id,device_id,object_key,digest,metadata,valid_until,created_at,expires_at,verified) VALUES('fresh-artifact','recipient',$1,'connection',$2,'synthetic-artifact','synthetic',$3,999999,0,999999,true)",
    [job.id, d.id, JSON.stringify({ generation: 1 })],
  );
  await h.db.query(
    'UPDATE artifacts SET connection_owner_id=$2,access_grant_id=$3,access_grant_generation=1 WHERE id=$1',
    ['fresh-artifact', 'owner', h.offered.id],
  );
  const tickets = new Tickets(
    h.db,
    () => 100,
    (owner, device, force) => devices.checkRegistered(owner, device, force),
  );
  await tickets.issue('recipient', 'fresh-artifact');
  enabled = false;
  await expect(tickets.issue('recipient', 'fresh-artifact')).rejects.toThrow('DEVICE_NOT_READY');
  expect(
    (await h.db.query<{ status: string }>('SELECT status FROM devices WHERE id=$1', [d.id])).rows[0]
      .status,
  ).toBe('disabled');
  await h.sharing.revoke('owner', h.offered.id);
  const { grantId: nextId } = await h.sharing.share('owner', h.publicId);
  const next = { id: nextId, generation: 2 };

  expect((await h.db.query('SELECT id FROM signing_jobs')).rows).toHaveLength(0);
  expect((await h.db.query('SELECT id FROM signing_artifacts')).rows).toHaveLength(0);
  expect((await h.db.query('SELECT id FROM signing_devices')).rows).toHaveLength(0);
});
it('owner and multiple recipients preserve the same Apple bundle with separate consent records', async () => {
  const h = await accepted();
  const otherId = (
    await h.db.query<{ public_profile_id: string }>(
      "SELECT public_profile_id FROM users WHERE id='other'",
    )
  ).rows[0].public_profile_id;
  const { grantId } = await h.sharing.share('owner', otherId);
  const grant = { id: grantId, generation: 1 };

  const mappings = new MappingService(h.db);
  const rows = await Promise.all(
    ['owner', 'recipient', 'other'].map((principal) =>
      mappings.choose(principal, 'connection', 'com.synthetic.shared', true),
    ),
  );
  expect(new Set(rows.map((r) => r.id)).size).toBe(3);
  expect(rows.map((r) => r.target_id)).toEqual(Array(3).fill('com.synthetic.shared'));
  expect((await h.db.query('SELECT owner_id FROM mappings ORDER BY owner_id')).rows).toEqual([
    { owner_id: 'other' },
    { owner_id: 'owner' },
    { owner_id: 'recipient' },
  ]);
});
