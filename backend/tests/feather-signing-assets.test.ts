import { it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { featherFixture } from './helpers/feather-assets';
import { Failure } from '../packages/core/src/shared';
import { AppleSharing } from '../packages/core/src/apple/access';
it('reuses identity and exports real encrypted P12 under isolated secret purpose', async () => {
  const f = await featherFixture();
  expect((await f.assets.ensure('o')).state).toBe('ready');
  const a = await f.assets.bundle('o'),
    b = await f.assets.bundle('o');
  expect(a.identityId).toBe(b.identityId);
  expect(f.certificatePosts).toBe(1);
  expect(f.contexts.every((c) => JSON.parse(c).purpose === 'feather-signing-key')).toBe(true);
  expect(JSON.stringify(await f.assets.status('o'))).not.toMatch(
    /PRIVATE KEY|p12|password|secret_ref|csr/,
  );
  const dir = mkdtempSync(join(tmpdir(), 'feather-p12-'));
  try {
    writeFileSync(join(dir, 'p12'), Buffer.from(a.p12, 'base64'));
    writeFileSync(join(dir, 'password'), a.password);
    expect(
      execFileSync(
        'openssl',
        ['pkcs12', '-in', join(dir, 'p12'), '-passin', 'file:' + join(dir, 'password'), '-nodes'],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      ).toString(),
    ).toContain('PRIVATE KEY');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
it('never repeats uncertain certificate POST even when list is temporarily empty', async () => {
  const f = await featherFixture();
  f.setAfterCertificate(async () => {
    throw Error('timeout');
  });
  expect((await f.assets.ensure('o')).state).toBe('reconciling');
  const cert = f.certs.splice(0)[0];
  expect((await f.assets.ensure('o')).state).toBe('reconciling');
  expect(f.certificatePosts).toBe(1);
  f.certs.push(cert);
  expect((await f.assets.ensure('o')).state).toBe('ready');
});
it('serializes creation without a transaction spanning Apple', async () => {
  const f = await featherFixture();
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((r) => (release = r)),
    ready = new Promise<void>((r) => (entered = r));
  f.setBeforeCertificate(async () => {
    entered();
    await gate;
  });
  const first = f.assets.ensure('o');
  await ready;
  expect((await f.assets.ensure('o')).state).toBe('reconciling');
  release();
  await first;
  expect(f.certificatePosts).toBe(1);
});
it('reports quota action required without remote revoke', async () => {
  const f = await featherFixture();
  f.setBeforeCertificate(async () => {
    throw new Failure('APPLE_OPERATION_REJECTED', 409);
  });
  expect((await f.assets.ensure('o')).state).toBe('action_required');
  await f.assets.ensure('o');
  expect(f.certificatePosts).toBe(1);
  expect(f.revokes).toBe(0);
});
it('rejects generation race and cleans old key without remote revoke', async () => {
  const f = await featherFixture();
  f.setAfterCertificate(async () => {
    await f.db.query("UPDATE connections SET generation=2 WHERE id='c'");
  });
  await expect(f.assets.ensure('o')).rejects.toThrow();
  await f.assets.maintain();
  expect(
    (
      await f.db.query(
        "SELECT id FROM secrets WHERE purpose='feather-signing-key' AND deleted_at IS NULL",
      )
    ).rows,
  ).toHaveLength(0);
  expect(f.revokes).toBe(0);
});
it('shares common identity but denies member revoke and rechecks grant after KMS', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  await f.db.query("UPDATE users SET public_profile_id=$1 WHERE id='m'", [
    'profile_' + 'b'.repeat(32),
  ]);
  const sharing = new AppleSharing(f.db, Date.now),
    grant = await sharing.share('o', 'profile_' + 'b'.repeat(32));
  expect((await f.assets.bundle('m')).identityId).toBe((await f.assets.bundle('o')).identityId);
  await expect(f.assets.revoke('m')).rejects.toThrow('OWNER_REQUIRED');
  f.setUnwrap(async () => {
    await sharing.revoke('o', grant.grantId);
  });
  await expect(f.assets.bundle('m')).rejects.toThrow();
  expect(f.revokes).toBe(0);
});
it('rejects stale certificate and retires expired identity locally', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  f.certs.length = 0;
  await expect(f.assets.bundle('o')).rejects.toThrow('CERTIFICATE_NOT_CURRENT');
  f.advance(366 * 86400000);
  await f.assets.maintain();
  expect(f.revokes).toBe(0);
  expect((await f.assets.status('o')).state).toBe('missing');
});
it('explicit owner revoke destroys key', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  await f.assets.revoke('o');
  expect(f.revokes).toBe(1);
  expect((await f.assets.status('o')).state).toBe('revoked');
  await expect(f.assets.bundle('o')).rejects.toThrow();
  expect(
    (
      await f.db.query(
        "SELECT id FROM secrets WHERE purpose='feather-signing-key' AND ciphertext<>''",
      )
    ).rows,
  ).toHaveLength(0);
});
it('requires client schema only with native feature enabled and additive migration upgrades old schema', async () => {
  const f = await featherFixture();
  await f.db.query("UPDATE users SET role='admin' WHERE id='o'");
  const { assertInitializedDatabase } =
    await import('../packages/core/src/infrastructure/database-init');
  await f.db.exec('DROP TABLE feather_profile_operations; DROP TABLE feather_signing_identities;');
  await expect(assertInitializedDatabase(f.db)).resolves.toBeUndefined();
  await expect(assertInitializedDatabase(f.db, { native: true })).rejects.toThrow(
    'DATABASE_UNINITIALIZED',
  );
  const { readFile } = await import('node:fs/promises');
  await f.db.exec(
    await readFile('backend/packages/db/migrations/20261101-feather-signing.sql', 'utf8'),
  );
  await f.db.exec(
    await readFile('backend/packages/db/migrations/20261101-feather-renewal.sql', 'utf8'),
  );
  await expect(assertInitializedDatabase(f.db, { native: true })).resolves.toBeUndefined();
});
it.each(['disconnected', 'deleted'])(
  'maintenance destroys client material after %s without remote revoke',
  async (kind) => {
    const f = await featherFixture();
    await f.assets.ensure('o');
    if (kind === 'deleted') await f.db.query("UPDATE users SET deleted_at=1 WHERE id='o'");
    else await f.db.query("UPDATE connections SET state='disconnected' WHERE id='c'");
    await f.assets.maintain();
    expect(
      (
        await f.db.query(
          "SELECT id FROM secrets WHERE purpose='feather-signing-key' AND ciphertext<>''",
        )
      ).rows,
    ).toHaveLength(0);
    expect(f.revokes).toBe(0);
    await expect(f.assets.bundle('o')).rejects.toThrow();
  },
);
it('explicit ensure retries certain rejection with durable key, while maintenance only reconciles uncertain submission', async () => {
  const f = await featherFixture();
  f.setBeforeCertificate(async () => {
    throw new Failure('APPLE_OPERATION_REJECTED', 409);
  });
  const rejected = await f.assets.ensure('o');
  await f.assets.maintain();
  expect(f.certificatePosts).toBe(1);
  f.setBeforeCertificate(async () => {});
  const recovered = await f.assets.ensure('o', { retry: true });
  expect(recovered.state).toBe('ready');
  expect(recovered.identityId).toBe(rejected.identityId);
  expect(f.contexts).toHaveLength(1);
});
it('explicit ensure after revoke creates a fresh revision, without silently revoking on maintenance', async () => {
  const f = await featherFixture();
  const first = await f.assets.ensure('o');
  await f.assets.revoke('o');
  await f.assets.maintain();
  expect(f.certificatePosts).toBe(1);
  const second = await f.assets.ensure('o', { retry: true });
  expect(second.state).toBe('ready');
  expect(second.identityId).not.toBe(first.identityId);
  expect(second.revision).toBe(2);
  expect(f.revokes).toBe(1);
});
it('maintenance reconciles uncertain creation after restart without another POST', async () => {
  const f = await featherFixture();
  f.setAfterCertificate(async () => {
    throw Error('timeout');
  });
  await f.assets.ensure('o');
  await f.assets.maintain();
  expect((await f.assets.status('o')).state).toBe('ready');
  expect(f.certificatePosts).toBe(1);
});
it('default ensure never undoes explicit revoke and a member cannot request retry', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  await f.db.query("UPDATE users SET public_profile_id=$1 WHERE id='m'", [
    'profile_' + 'b'.repeat(32),
  ]);
  await new AppleSharing(f.db, Date.now).share('o', 'profile_' + 'b'.repeat(32));
  await f.assets.revoke('o');
  expect((await f.assets.ensure('o')).state).toBe('revoked');
  expect((await f.assets.ensure('m')).state).toBe('revoked');
  await expect(f.assets.ensure('m', { retry: true })).rejects.toThrow('OWNER_REQUIRED');
  expect(f.certificatePosts).toBe(1);
});
it('rejects foreign certificate material instead of publishing its P12', async () => {
  const f = await featherFixture(),
    create = f.api.certificate,
    foreign = await f.material.generate('ZZZZZZZZZZ');
  f.api.certificate = async () => create(foreign.csr, foreign.spkiSha256);
  try {
    await expect(f.assets.ensure('o')).rejects.toThrow('CERTIFICATE_IDENTITY_MISMATCH');
    await expect(f.assets.bundle('o')).rejects.toThrow('SIGNING_IDENTITY_NOT_READY');
  } finally {
    foreign.privateKey.fill(0);
  }
});
it('cannot export a server distribution key through the client Vault purpose', async () => {
  const f = await featherFixture();
  const identity = await f.assets.ensure('o');
  await f.db.query(
    "UPDATE secrets SET purpose='distribution-key' WHERE id=(SELECT secret_ref FROM feather_signing_identities WHERE id=$1)",
    [identity.identityId],
  );
  await expect(f.assets.bundle('o')).rejects.toThrow('SECRET_UNAVAILABLE');
});
it('expired lease cannot commit and next reconciliation does not repeat certificate POST', async () => {
  const f = await featherFixture();
  f.setAfterCertificate(async () => {
    f.advance(151000);
  });
  await expect(f.assets.ensure('o')).rejects.toThrow('SIGNING_OPERATION_CHANGED');
  expect((await f.assets.ensure('o', { retry: true })).state).toBe('ready');
  expect(f.certificatePosts).toBe(1);
});
it('client and server job readers are purpose-isolated', async () => {
  const f = await featherFixture(),
    identity = await f.assets.ensure('o');
  const secret = (
    await f.db.query<{ secret_ref: string }>(
      'SELECT secret_ref FROM feather_signing_identities WHERE id=$1',
      [identity.identityId],
    )
  ).rows[0].secret_ref;
  await f.db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','a.ipa','a.ipa',1,'digest','uploaded',1,$1)",
    [Date.now() + 86400000],
  );
  await f.db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_owner_id,connection_generation,state,idempotency_key,created_at,updated_at,lease_token,lease_expires) VALUES('j','o','u','d1','c','o',1,'provisioning','k',1,1,'lease',$1)",
    [Date.now() + 86400000],
  );
  await expect(f.vault.openForJob('o', secret, 'j', 'lease')).rejects.toThrow('SECRET_UNAVAILABLE');
  const server = await f.vault.seal('o', 'c', 'distribution-key', Buffer.from('server key'));
  expect((await f.vault.openForJob('o', server, 'j', 'lease')).toString()).toBe('server key');
});
it('maintenance destroys encrypted keys orphaned before journal attachment', async () => {
  const f = await featherFixture();
  const orphan = await f.vault.seal(
    'o',
    'c',
    'feather-signing-key',
    Buffer.from('never submitted'),
  );
  await f.assets.maintain();
  expect(
    (
      await f.db.query<{ ciphertext: string }>('SELECT ciphertext FROM secrets WHERE id=$1', [
        orphan,
      ])
    ).rows[0].ciphertext,
  ).toBe('');
  expect(f.certificatePosts).toBe(0);
});
it('explicit certificate delete is idempotent after an ambiguous successful Apple response', async () => {
  const { AppleClient } = await import('../packages/core/src/infrastructure/apple-api');
  const { AppleProvisioningApi } = await import('../packages/core/src/apple/provisioning-client');
  let request: { method: string; url: string } | undefined;
  const api = new AppleProvisioningApi(
    new AppleClient(
      async () => 'jwt',
      async (method, url) => {
        request = { method, url };
        return { status: 404, data: { errors: [] } };
      },
    ),
    Date.now,
  );
  await expect(api.revokeCertificate('already-deleted')).resolves.toBeUndefined();
  expect(request).toEqual({
    method: 'DELETE',
    url: 'https://api.appstoreconnect.apple.com/v1/certificates/already-deleted',
  });
  await expect(api.revokeCertificate('../profiles')).rejects.toThrow(
    'INVALID_CERTIFICATE_RESOURCE',
  );
});
it('preserves unresolved owner revoke through expiry until explicit owner recovery', async () => {
  const f = await featherFixture();
  f.setCertificateDays(1);
  const first = await f.assets.ensure('o');
  await f.db.query("UPDATE users SET public_profile_id=$1 WHERE id='m'", [
    'profile_' + 'b'.repeat(32),
  ]);
  await new AppleSharing(f.db, Date.now).share('o', 'profile_' + 'b'.repeat(32));
  const remove = f.api.revokeCertificate;
  f.api.revokeCertificate = async (id) => {
    await remove(id);
    throw Error('lost DELETE response');
  };
  await expect(f.assets.revoke('o')).rejects.toThrow('lost DELETE response');
  f.setCertificateDays(365);
  f.advance(2 * 86400000);
  await f.assets.maintain();
  expect((await f.assets.status('o')).state).toBe('revoked');
  expect((await f.assets.ensure('o')).state).toBe('revoked');
  expect((await f.assets.ensure('m')).state).toBe('revoked');
  await f.assets.maintain();
  expect(f.certificatePosts).toBe(1);
  await expect(f.assets.ensure('m', { retry: true })).rejects.toThrow('OWNER_REQUIRED');
  const recovered = await f.assets.ensure('o', { retry: true });
  expect(recovered.state).toBe('ready');
  expect(recovered.identityId).not.toBe(first.identityId);
  expect(recovered.revision).toBe(2);
  expect(f.certificatePosts).toBe(2);
});
