import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { createDatabase } from './database';
import { ownAuthority } from './seed-authority';
import { Vault } from '../../packages/core/src/apple/vault';
import { OpenSslSigningMaterial } from '../../packages/core/src/feather/signing-material';
import {
  FeatherSigningAssets,
  type FeatherSigningPorts,
} from '../../packages/core/src/feather/signing-assets';
import type {
  ControlResource,
  ControlProfileVerifier,
} from '../../packages/core/src/devices/eligibility';
import { hash } from '../../packages/core/src/shared';
export async function featherFixture() {
  const db = await createDatabase();
  let now = Date.now();
  let certificateDays = 365;
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('o','owner@test',1),('m','member@test',1)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
  );
  for (const [id, l] of [
    ['d1', 'A'],
    ['d2', 'B'],
  ])
    await db.query(
      "INSERT INTO devices(id,owner_id,connection_id,name,status,udid,udid_hash,apple_resource_id,connection_generation,enrollment_verified_at) VALUES($1,'o','c',$1,'ready',$2,$3,$4,1,1)",
      [id, l.repeat(40), hash(l.repeat(40)), 'apple-' + id],
    );
  await ownAuthority(db);
  const contexts: string[] = [];
  let onUnwrap = async () => {};
  const vault = new Vault(
    db,
    {
      generate: async (context) => {
        contexts.push(context);
        return { plaintext: Buffer.alloc(32, 7), wrapped: 'test-kms' };
      },
      unwrap: async () => {
        await onUnwrap();
        return Buffer.alloc(32, 7);
      },
    },
    () => now,
  );
  const material = new OpenSslSigningMaterial();
  const certs: { id: string; certificate: string }[] = [],
    bundles: (ControlResource & { type: string })[] = [],
    profiles: (ControlResource & { type: string })[] = [];
  let certificatePosts = 0,
    profilePosts = 0,
    revokes = 0;
  let beforeCertificate = async () => {},
    afterCertificate = async () => {},
    afterProfile = async () => {};
  let receiptPatch: Record<string, unknown> = {};
  const api: Awaited<ReturnType<FeatherSigningPorts['api']>> = {
    findCertificates: async (spki) =>
      certs.filter(
        (c) =>
          createHash('sha256')
            .update(
              new X509Certificate(c.certificate).publicKey.export({ type: 'spki', format: 'der' }),
            )
            .digest('hex') === spki,
      ),
    certificate: async (csr) => {
      certificatePosts++;
      await beforeCertificate();
      const saved = (
        await db.query<{ secret_ref: string }>(
          "SELECT secret_ref FROM feather_signing_identities WHERE state='submitted'",
        )
      ).rows[0];
      if (!saved?.secret_ref) throw Error('key not durable');
      const dir = mkdtempSync(join(tmpdir(), 'feather-test-ca-'));
      let certificate: string;
      try {
        writeFileSync(join(dir, 'csr'), csr);
        execFileSync(
          'openssl',
          [
            'req',
            '-x509',
            '-newkey',
            'rsa:2048',
            '-nodes',
            '-keyout',
            join(dir, 'ca.key'),
            '-out',
            join(dir, 'ca.crt'),
            '-subj',
            '/CN=Test CA',
            '-days',
            '365',
          ],
          { stdio: 'ignore' },
        );
        execFileSync(
          'openssl',
          [
            'x509',
            '-req',
            '-in',
            join(dir, 'csr'),
            '-CA',
            join(dir, 'ca.crt'),
            '-CAkey',
            join(dir, 'ca.key'),
            '-CAcreateserial',
            '-out',
            join(dir, 'cert'),
            '-days',
            String(certificateDays),
          ],
          { stdio: 'ignore' },
        );
        certificate = readFileSync(join(dir, 'cert'), 'utf8');
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
      const cert = new X509Certificate(certificate);
      now = Math.max(now, Date.parse(cert.validFrom) + 1000);
      const result = { id: 'cert-' + certificatePosts, certificate };
      certs.push(result);
      await afterCertificate();
      return {
        resource: { id: result.id, type: 'certificates', attributes: {} },
        certificate,
        expiresAt: Date.parse(cert.validTo),
        teamId: 'ABCDEFGHIJ',
      };
    },
    revokeCertificate: async (id) => {
      revokes++;
      const i = certs.findIndex((c) => c.id === id);
      if (i >= 0) certs.splice(i, 1);
    },
    rawDevice: async (_u, id) => ({ id, status: 'ENABLED' }),
    findBundles: async (identifier) =>
      bundles.filter((b) => b.attributes.identifier === identifier),
    bundle: async (identifier) => {
      const b = { type: 'bundleIds', id: 'bundle-' + bundles.length, attributes: { identifier } };
      bundles.push(b);
      return b;
    },
    findProfiles: async (bundleId, name) =>
      profiles.filter((p) => {
        const relation = p.relationships?.bundleId?.data;
        return p.attributes.name === name && !Array.isArray(relation) && relation?.id === bundleId;
      }),
    profile: async (request) => {
      profilePosts++;
      const p = {
        type: 'profiles',
        id: 'profile-' + profilePosts,
        relationships: { bundleId: { data: { type: 'bundleIds', id: request.bundleId } } },
        attributes: {
          name: request.name,
          profileState: 'ACTIVE',
          profileType: 'IOS_APP_ADHOC',
          profileContent: Buffer.from(JSON.stringify(request)).toString('base64'),
        },
      };
      profiles.push(p);
      await afterProfile();
      return p;
    },
  };
  const verify: ControlProfileVerifier = async (input) => {
    const request = JSON.parse(input.cms.toString());
    return {
      cmsSha256: input.cmsSha256,
      teamId: input.expected.teamId,
      bundleId: input.expected.bundleId,
      deviceUdids: request.deviceIds.map((id: string) =>
        id === 'apple-d1' ? 'A'.repeat(40) : 'B'.repeat(40),
      ),
      certificateSha256s: [input.expected.certificateSha256],
      expiresAt: now + 86400000,
      profileType: 'ad-hoc',
      entitlements: {
        'application-identifier': input.expected.teamId + '.' + input.expected.bundleId,
        'com.apple.developer.team-identifier': input.expected.teamId,
        'get-task-allow': false,
        'keychain-access-groups': [input.expected.teamId + '.*'],
      },
      ...receiptPatch,
    };
  };
  const assets = new FeatherSigningAssets(db, {
    api: async () => api,
    material,
    vault,
    verify,
    now: () => now,
  });
  return {
    db,
    assets,
    api,
    vault,
    material,
    certs,
    profiles,
    bundles,
    contexts,
    get certificatePosts() {
      return certificatePosts;
    },
    get profilePosts() {
      return profilePosts;
    },
    get revokes() {
      return revokes;
    },
    setNow: (value: number) => (now = value),
    setCertificateDays: (days: number) => (certificateDays = days),
    advance: (ms: number) => (now += ms),
    setBeforeCertificate: (f: () => Promise<void>) => (beforeCertificate = f),
    setAfterCertificate: (f: () => Promise<void>) => (afterCertificate = f),
    setAfterProfile: (f: () => Promise<void>) => (afterProfile = f),
    setUnwrap: (f: () => Promise<void>) => (onUnwrap = f),
    setReceipt: (v: Record<string, unknown>) => (receiptPatch = v),
  };
}
