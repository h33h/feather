import { afterEach, expect, it } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { connectionFixture, deviceFixture, loginFixture } from './helpers/login';
import { ClientInstallations } from '../packages/core/src/application/client-installations';
import { LocalClientRelease } from '../packages/core/src/infrastructure/client-release';
import { JobsActions } from '../packages/core/src/signing/jobs-actions';
import { ReceiveUpload } from '../packages/core/src/application/receive-upload';
import { PersonalObjects, PersonalStorage } from '../packages/core/src/library/personal-storage';
import { Tickets } from '../packages/core/src/library/tickets';
import { RequestAuthorization } from '../packages/core/src/application/request-authorization';
import { DeviceOnboarding } from '../packages/core/src/devices/onboarding';
import { Failure } from '../packages/core/src/shared';
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});
async function fixture() {
  const db = await createDatabase(),
    user = await loginFixture(db, 'installer', 1000);
  const connection = await connectionFixture(db, user.ownerId, 'TEAM'),
    device = await deviceFixture(db, user.ownerId, connection.id, 'Phone', '18.0');
  const directory = await mkdtemp(path.join(tmpdir(), 'client-install-'));
  directories.push(directory);
  const file = path.join(directory, 'official.ipa'),
    bytes = 'official pinned client',
    digest = createHash('sha256').update(bytes).digest('hex');
  await writeFile(file, bytes);
  const objects = new PersonalObjects(db, path.join(directory, 'objects'), () => 1000, {
    maxFile: 1024,
    ownerQuota: 8192,
    globalQuota: 16384,
    minimumFree: 0,
    retentionMs: 86400000,
  });
  await objects.recover();
  const jobs = new JobsActions(db, () => 1000),
    storage = new PersonalStorage(objects),
    receive = new ReceiveUpload(db, storage, jobs);
  const release = new LocalClientRelease({
    ISIGN_CLIENT_IPA_PATH: file,
    ISIGN_CLIENT_IPA_SHA256: digest,
    ISIGN_CLIENT_VERSION: '2.0',
  });
  const remoteDevice = { status: 'ENABLED' };
  const devices = new DeviceOnboarding(
    db,
    {
      find: async () => [],
      register: async () => {
        throw new Error('UNEXPECTED_DEVICE_REGISTRATION');
      },
      rawDevice: async (_udid, resourceId) => ({ id: resourceId, status: remoteDevice.status }),
    },
    () => 1000,
  );
  const options = {
    db,
    release,
    jobs,
    receive,
    authorization: new RequestAuthorization(db, () => 1000),
    devices,
    tickets: new Tickets(
      db,
      () => 1000,
      (owner, device, force) => devices.checkRegistered(owner, device, force),
    ),
    now: () => 1000,
  };
  const installer = new ClientInstallations(options);
  return { db, user, connection, device, file, digest, installer, jobs, options, remoteDevice };
}
it('persists one pinned source and job across concurrent repeated keys and a new scenario instance', async () => {
  const f = await fixture(),
    input = { deviceId: f.device.id, key: 'request-1' };
  const results = await Promise.all([
    f.installer.begin(f.user.ownerId, input),
    f.installer.begin(f.user.ownerId, input),
  ]);
  expect(results[0].operationId).toBe(results[1].operationId);
  expect((await f.db.query('SELECT id FROM jobs')).rows).toHaveLength(1);
  expect((await f.db.query('SELECT id FROM uploads')).rows).toHaveLength(1);
  expect((await f.db.query('SELECT id FROM personal_objects')).rows).toHaveLength(1);
  expect(await new ClientInstallations(f.options).begin(f.user.ownerId, input)).toMatchObject({
    operationId: results[0].operationId,
    jobId: results[0].jobId,
    state: 'queued',
  });
  expect((await f.db.query('SELECT digest,provenance FROM uploads')).rows).toEqual([
    { digest: f.digest, provenance: { kind: 'isign-client', sha256: f.digest } },
  ]);
  const other = await deviceFixture(f.db, f.user.ownerId, f.connection.id, 'Other', '18.0');
  await expect(f.installer.begin(f.user.ownerId, { ...input, deviceId: other.id })).rejects.toThrow(
    'IDEMPOTENCY_BINDING_MISMATCH',
  );
});
it('rejects foreign operations and devices and fences current connection/device authority', async () => {
  const f = await fixture(),
    foreign = await loginFixture(f.db, 'foreign', 1000);
  await expect(
    f.installer.begin(foreign.ownerId, { deviceId: f.device.id, key: 'bad' }),
  ).rejects.toThrow('APPLE_ACCESS_REQUIRED');
  const result = await f.installer.begin(f.user.ownerId, { deviceId: f.device.id, key: 'one' });
  await expect(f.installer.view(foreign.ownerId, result.operationId)).rejects.toThrow('NOT_FOUND');
  await expect(f.installer.ticket(foreign.ownerId, result.operationId)).rejects.toThrow(
    'NOT_FOUND',
  );
  await f.db.query("UPDATE devices SET status='locally_removed' WHERE id=$1", [f.device.id]);
  await expect(f.installer.view(f.user.ownerId, result.operationId)).rejects.toThrow('NOT_FOUND');
});
it('returns a stable failed operation after receive interruption and never creates another job for its key', async () => {
  const f = await fixture();
  const release = {
    status: f.options.release.status.bind(f.options.release),
    open: async () => ({
      digest: f.digest,
      bytes: (async function* () {
        yield Buffer.from('partial');
        throw new Failure('CLIENT_RELEASE_UNAVAILABLE', 503);
      })(),
    }),
  };
  const installer = new ClientInstallations({ ...f.options, release });
  const first = await installer.begin(f.user.ownerId, {
    deviceId: f.device.id,
    key: 'interrupted',
  });
  expect(first).toMatchObject({ state: 'failed', reason: 'CLIENT_RELEASE_UNAVAILABLE' });
  expect(
    await installer.begin(f.user.ownerId, { deviceId: f.device.id, key: 'interrupted' }),
  ).toMatchObject({ operationId: first.operationId, state: 'failed' });
  expect((await f.db.query('SELECT id FROM jobs')).rows).toHaveLength(1);
  expect(
    (await f.db.query("SELECT id FROM personal_objects WHERE state='live'")).rows,
  ).toHaveLength(0);
});
it('fails deployment readiness for absent schema and advertises safe installer unavailability', async () => {
  const f = await fixture();
  await f.db.query('DROP TABLE client_installations');
  await expect(f.installer.assertReady()).rejects.toThrow('CLIENT_INSTALLER_MIGRATION_REQUIRED');
  expect(await f.installer.release()).toEqual({
    name: 'iSign Client',
    available: false,
    reason: 'CLIENT_INSTALLER_MIGRATION_REQUIRED',
  });
});
it('issues tickets only for the operation artifact under current authority and verified source provenance', async () => {
  const f = await fixture(),
    result = await f.installer.begin(f.user.ownerId, { deviceId: f.device.id, key: 'ready' });
  await expect(f.installer.ticket(f.user.ownerId, result.operationId)).rejects.toThrow(
    'CLIENT_INSTALL_NOT_READY',
  );
  await f.db.query("UPDATE jobs SET state='ready' WHERE id=$1", [result.jobId]);
  await f.db.query(
    "INSERT INTO artifacts(id,job_id,owner_id,device_id,connection_id,connection_owner_id,object_key,digest,metadata,verified,created_at,expires_at,valid_until) VALUES('artifact',$1,$2,$3,$4,$2,'signed.ipa','digest',$5,true,1000,20000,20000)",
    [
      result.jobId,
      f.user.ownerId,
      f.device.id,
      f.connection.id,
      JSON.stringify({
        bundleId: 'normalized.isign.team',
        version: '2.0',
        title: 'iSign Client',
        generation: 1,
      }),
    ],
  );
  expect(await f.installer.view(f.user.ownerId, result.operationId)).toMatchObject({
    artifactId: 'artifact',
    version: '2.0',
    state: 'ready',
  });
  expect(await f.installer.ticket(f.user.ownerId, result.operationId)).toMatchObject({
    ticket: expect.any(String),
    expiresAt: 20000,
  });
  await f.db.query("UPDATE uploads SET provenance='{}'::jsonb");
  await expect(f.installer.view(f.user.ownerId, result.operationId)).rejects.toThrow('NOT_FOUND');
});
it('allows an existing shared Apple grant and immediately fences revoked grants', async () => {
  const f = await fixture(),
    recipient = await loginFixture(f.db, 'shared-recipient', 1000);
  const { AppleSharing } = await import('../packages/core/src/apple/access');
  const sharing = new AppleSharing(f.db, () => 1000);
  const profile = (
    await f.db.query<{ public_profile_id: string }>(
      'SELECT public_profile_id FROM users WHERE id=$1',
      [recipient.ownerId],
    )
  ).rows[0];
  const { grantId } = await sharing.share(f.user.ownerId, profile.public_profile_id);
  await f.db.query(
    'UPDATE devices SET owner_id=$2,access_grant_id=$3,access_grant_generation=1 WHERE id=$1',
    [f.device.id, recipient.ownerId, grantId],
  );
  const result = await f.installer.begin(recipient.ownerId, {
    deviceId: f.device.id,
    key: 'shared',
  });
  expect(result.state).toBe('queued');
  expect(
    (await f.db.query('SELECT owner_id,connection_owner_id,access_grant_id FROM jobs')).rows,
  ).toEqual([
    { owner_id: recipient.ownerId, connection_owner_id: f.user.ownerId, access_grant_id: grantId },
  ]);
  await expect(f.installer.view(f.user.ownerId, result.operationId)).rejects.toThrow('NOT_FOUND');
  await sharing.revoke(f.user.ownerId, grantId);
  await expect(f.installer.view(recipient.ownerId, result.operationId)).rejects.toThrow(
    'NOT_FOUND',
  );
  await expect(f.installer.ticket(recipient.ownerId, result.operationId)).rejects.toThrow(
    'NOT_FOUND',
  );
  await expect(
    f.installer.begin(recipient.ownerId, { deviceId: f.device.id, key: 'after-revoke' }),
  ).rejects.toThrow('APPLE_ACCESS_REQUIRED');
});
it('does not enqueue a changed template after the initial release inspection', async () => {
  const f = await fixture();
  const release = {
    status: f.options.release.status.bind(f.options.release),
    open: async () => {
      const source = await f.options.release.open();
      await writeFile(f.file, 'mutated');
      return source;
    },
  };
  const installer = new ClientInstallations({ ...f.options, release });
  expect(
    await installer.begin(f.user.ownerId, { deviceId: f.device.id, key: 'mutated' }),
  ).toMatchObject({ state: 'failed', reason: 'CLIENT_RELEASE_CHECKSUM_MISMATCH' });
  expect((await f.db.query("SELECT id FROM jobs WHERE state='queued'")).rows).toEqual([]);
  expect((await f.db.query("SELECT id FROM personal_objects WHERE state='live'")).rows).toEqual([]);
});
it('recovers a process-interrupted receive as the same failed operation on restart', async () => {
  const f = await fixture(),
    key = 'restart';
  const { hash } = await import('../packages/core/src/shared');
  const submission = await f.jobs.beginSubmission(f.user.ownerId, {
    deviceId: f.device.id,
    key: 'client_' + hash(key),
    name: 'iSign Client.ipa',
    source: 'upload',
    provenance: { kind: 'isign-client', sha256: f.digest },
  });
  await f.db.query(
    "INSERT INTO client_installations(id,owner_id,request_key,job_id,device_id,release_sha256,receive_started_at,created_at) VALUES('interrupted',$1,$2,$3,$4,$5,1000,1000)",
    [f.user.ownerId, key, submission.jobId, f.device.id, f.digest],
  );
  await f.jobs.queue.recoverReceiving();
  expect(
    await new ClientInstallations(f.options).begin(f.user.ownerId, { deviceId: f.device.id, key }),
  ).toMatchObject({
    operationId: 'interrupted',
    jobId: submission.jobId,
    state: 'failed',
    reason: 'SOURCE_RECEIVE_INTERRUPTED',
  });
  expect((await f.db.query('SELECT id FROM jobs')).rows).toHaveLength(1);
});
it('cleans installation locators when the existing job retention lifecycle deletes jobs', async () => {
  const f = await fixture(),
    result = await f.installer.begin(f.user.ownerId, { deviceId: f.device.id, key: 'cleanup' });
  await f.jobs.cancel(f.user.ownerId, result.jobId);
  const { cleanupHistory } = await import('../packages/core/src/library/installation-history');
  await cleanupHistory(f.db, 1000 + 2592000000);
  expect((await f.db.query('SELECT id FROM client_installations')).rows).toEqual([]);
});
it('turns a completed job with an expired or unverified artifact into a retryable installer failure', async () => {
  const f = await fixture(),
    result = await f.installer.begin(f.user.ownerId, { deviceId: f.device.id, key: 'expired' });
  await f.db.query("UPDATE jobs SET state='ready' WHERE id=$1", [result.jobId]);
  expect(await f.installer.view(f.user.ownerId, result.operationId)).toMatchObject({
    state: 'failed',
    reason: 'CLIENT_INSTALL_ARTIFACT_UNAVAILABLE',
  });
  await expect(f.installer.ticket(f.user.ownerId, result.operationId)).rejects.toThrow(
    'CLIENT_INSTALL_NOT_READY',
  );
});
it('checks live Apple device registration before admission and refuses a disabled device', async () => {
  const f = await fixture();
  f.remoteDevice.status = 'DISABLED';
  await expect(
    f.installer.begin(f.user.ownerId, { deviceId: f.device.id, key: 'disabled' }),
  ).rejects.toThrow('DEVICE_NOT_READY');
  expect((await f.db.query('SELECT id FROM jobs')).rows).toEqual([]);
});
