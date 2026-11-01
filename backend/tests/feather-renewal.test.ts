import { expect, it } from 'vitest';
import { featherFixture } from './helpers/feather-assets';
import { Failure } from '../packages/core/src/shared';
const day = 86400000;
const request = { deviceIds: ['d1'], bundles: [{ bundleId: 'com.example.app', entitlements: {} }] };
async function renewalFixture() {
  const f = await featherFixture();
  f.setCertificateDays(40);
  const first = await f.assets.ensure('o');
  f.setCertificateDays(365);
  return { f, first, threshold: first.expiresAt! - 30 * day };
}
it('renews exactly at the 30-day boundary and atomically publishes a new revision without remote revoke', async () => {
  const { f, first, threshold } = await renewalFixture();
  f.setNow(threshold - 1);
  expect((await f.assets.ensure('o')).identityId).toBe(first.identityId);
  expect(f.certificatePosts).toBe(1);
  const oldProfiles = await f.assets.profiles('o', request);
  f.setNow(threshold);
  const renewed = await f.assets.ensure('o');
  await expect(f.assets.profileStatus('o', oldProfiles.operationId)).rejects.toThrow(
    'SIGNING_IDENTITY_CHANGED',
  );
  expect(renewed.state).toBe('ready');
  expect(renewed.identityId).not.toBe(first.identityId);
  expect(renewed.revision).toBe(2);
  expect((await f.assets.bundle('o')).identityId).toBe(renewed.identityId);
  expect(f.certificatePosts).toBe(2);
  expect(f.revokes).toBe(0);
  expect(f.certs).toHaveLength(2);
});
it.each(['APPLE_OPERATION_REJECTED', 'APPLE_ACCESS_ACTION_REQUIRED'])(
  'retains valid exports/profiles on renewal rejection %s and only retries explicitly',
  async (code) => {
    const { f, first, threshold } = await renewalFixture();
    f.setNow(threshold);
    f.setBeforeCertificate(async () => {
      throw new Failure(code, 409);
    });
    const rejected = await f.assets.ensure('o');
    expect(rejected).toMatchObject({
      state: 'ready',
      identityId: first.identityId,
      renewal: { state: 'action_required' },
    });
    expect((await f.assets.bundle('o')).identityId).toBe(first.identityId);
    expect((await f.assets.profiles('o', request)).state).toBe('ready');
    await Promise.all([f.assets.ensure('o'), f.assets.maintain()]);
    expect(f.certificatePosts).toBe(2);
    f.setBeforeCertificate(async () => {});
    const renewed = await f.assets.ensure('o', { retry: true });
    expect(renewed.identityId).not.toBe(first.identityId);
    expect(renewed.revision).toBe(2);
    expect(f.contexts).toHaveLength(2);
    expect(f.certificatePosts).toBe(3);
    expect(f.revokes).toBe(0);
  },
);
it('reconciles uncertain renewal while retaining the old identity until proof succeeds', async () => {
  const { f, first, threshold } = await renewalFixture();
  f.setNow(threshold);
  f.setAfterCertificate(async () => {
    throw Error('lost certificate response');
  });
  expect((await f.assets.ensure('o')).identityId).toBe(first.identityId);
  expect(f.certificatePosts).toBe(2);
  const candidate = f.certs.pop()!;
  await f.assets.maintain();
  expect((await f.assets.ensure('o', { retry: true })).identityId).toBe(first.identityId);
  expect((await f.assets.bundle('o')).identityId).toBe(first.identityId);
  expect(f.certificatePosts).toBe(2);
  f.certs.push(candidate);
  await f.assets.maintain();
  expect((await f.assets.status('o')).identityId).not.toBe(first.identityId);
  expect(f.certificatePosts).toBe(2);
  expect(f.revokes).toBe(0);
});
it('concurrent ensure and maintenance share a renewal lease, and owner revoke fences its in-flight publication', async () => {
  const { f, first, threshold } = await renewalFixture();
  f.setNow(threshold);
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve)),
    ready = new Promise<void>((resolve) => (entered = resolve));
  f.setAfterCertificate(async () => {
    entered();
    await gate;
  });
  const renewing = f.assets.ensure('o');
  const outcome = renewing.then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  await Promise.race([
    ready,
    renewing.then(() => {
      throw Error('renewal did not start');
    }),
  ]);
  expect((await f.assets.bundle('o')).identityId).toBe(first.identityId);
  await Promise.all([f.assets.ensure('o'), f.assets.maintain()]);
  expect(f.certificatePosts).toBe(2);
  await f.assets.revoke('o');
  release();
  expect(await outcome).toMatchObject({ error: { code: 'SIGNING_OPERATION_CHANGED' } });
  await f.assets.maintain();
  expect((await f.assets.ensure('o')).state).toBe('revoked');
  await expect(f.assets.bundle('o')).rejects.toThrow('SIGNING_IDENTITY_NOT_READY');
  expect(f.certificatePosts).toBe(2);
  expect(f.revokes).toBe(1);
});
it('old expiry mid-renewal neither creates a second candidate nor repeats an uncertain POST', async () => {
  const { f, first, threshold } = await renewalFixture();
  f.setNow(threshold);
  f.setAfterCertificate(async () => {
    throw Error('timeout');
  });
  await f.assets.ensure('o');
  expect(f.certificatePosts).toBe(2);
  const candidate = f.certs.pop()!;
  f.setNow(first.expiresAt! + 1);
  await Promise.all([f.assets.ensure('o'), f.assets.maintain()]);
  await expect(f.assets.bundle('o')).rejects.toThrow('SIGNING_IDENTITY_NOT_READY');
  expect(f.certificatePosts).toBe(2);
  expect(f.contexts).toHaveLength(2);
  f.certs.push(candidate);
  await f.assets.maintain();
  expect((await f.assets.status('o')).revision).toBe(2);
  expect((await f.assets.bundle('o')).revision).toBe(2);
  expect(f.certificatePosts).toBe(2);
  expect(f.revokes).toBe(0);
});
it('maintenance itself initiates the 30-day renewal window', async () => {
  const { f, first, threshold } = await renewalFixture();
  f.setNow(threshold);
  await f.assets.maintain();
  expect((await f.assets.status('o')).identityId).not.toBe(first.identityId);
  expect(f.certificatePosts).toBe(2);
});
it('concurrent explicit retries after old expiry reuse the rejected candidate and one POST', async () => {
  const { f, first, threshold } = await renewalFixture();
  f.setNow(threshold);
  f.setBeforeCertificate(async () => {
    throw new Failure('APPLE_OPERATION_REJECTED', 409);
  });
  const rejected = await f.assets.ensure('o');
  f.setNow(first.expiresAt! + 1);
  await f.assets.maintain();
  expect((await f.assets.ensure('o')).state).toBe('action_required');
  expect(f.certificatePosts).toBe(2);
  let release!: () => void, entered!: () => void;
  const gate = new Promise<void>((r) => (release = r)),
    ready = new Promise<void>((r) => (entered = r));
  f.setBeforeCertificate(async () => {
    entered();
    await gate;
  });
  const retry = f.assets.ensure('o', { retry: true });
  await ready;
  await Promise.all([f.assets.ensure('o', { retry: true }), f.assets.maintain()]);
  expect(f.certificatePosts).toBe(3);
  expect(f.contexts).toHaveLength(2);
  release();
  expect((await retry).identityId).toBe(rejected.renewal!.identityId);
  expect((await f.assets.bundle('o')).revision).toBe(2);
  expect(f.revokes).toBe(0);
});
it('a renewal certificate with the wrong key/team cannot replace the valid current identity', async () => {
  const { f, first, threshold } = await renewalFixture();
  const create = f.api.certificate,
    foreign = await f.material.generate('ZZZZZZZZZZ');
  f.api.certificate = async () => create(foreign.csr, foreign.spkiSha256);
  f.setNow(threshold);
  try {
    await expect(f.assets.ensure('o')).rejects.toThrow('CERTIFICATE_IDENTITY_MISMATCH');
    expect((await f.assets.bundle('o')).identityId).toBe(first.identityId);
    expect((await f.assets.status('o')).renewal?.state).toBe('reconciling');
    expect(f.revokes).toBe(0);
  } finally {
    foreign.privateKey.fill(0);
  }
});
it('renewal migration preserves existing identities and constrains one candidate per connection generation', async () => {
  const { f, first, threshold } = await renewalFixture();
  const { readFile } = await import('node:fs/promises');
  await f.db.exec(
    "ALTER TABLE feather_signing_identities DROP COLUMN replacement_for CASCADE; CREATE UNIQUE INDEX feather_current_identity ON feather_signing_identities(connection_id,generation) WHERE state<>'retired';",
  );
  await f.db.exec(
    await readFile('backend/packages/db/migrations/20261101-feather-renewal.sql', 'utf8'),
  );
  expect((await f.assets.bundle('o')).identityId).toBe(first.identityId);
  f.setNow(threshold);
  f.setBeforeCertificate(async () => {
    throw new Failure('APPLE_OPERATION_REJECTED', 409);
  });
  await f.assets.ensure('o');
  await expect(
    f.db.query(
      "INSERT INTO feather_signing_identities(id,connection_id,owner_id,generation,revision,state,created_at,replacement_for) VALUES('duplicate','c','o',1,3,'pending',1,$1)",
      [first.identityId],
    ),
  ).rejects.toThrow();
  expect((await f.assets.bundle('o')).identityId).toBe(first.identityId);
});
it('serializes expiry cleanup with renewal publication while running KMS cleanup outside the transaction', async () => {
  const { f, first } = await renewalFixture();
  const { FeatherSigningAssets } = await import('../packages/core/src/feather/signing-assets');
  const retirements: boolean[] = [];
  let inTransaction = false;
  const observe = (sql: string, locked: boolean) => {
    if (sql.startsWith("UPDATE feather_signing_identities i SET state='retired'"))
      retirements.push(locked);
  };
  const db: typeof f.assets.db = {
    query: (sql, args) => {
      observe(sql, false);
      return f.db.query(sql, args);
    },
    close: () => f.db.close(),
    transaction: (work) =>
      f.db.transaction(async (tx) => {
        let locked = false;
        inTransaction = true;
        try {
          return await work({
            query: (sql, args) => {
              observe(sql, locked);
              if (sql === 'SELECT pg_advisory_xact_lock(736490)') locked = true;
              return tx.query(sql, args);
            },
          });
        } finally {
          inTransaction = false;
        }
      }),
  };
  const assets = new FeatherSigningAssets(db, {
    ...f.assets.ports,
    vault: {
      seal: f.vault.seal.bind(f.vault),
      openForClientSigning: f.vault.openForClientSigning.bind(f.vault),
      tombstone: async (...args) => {
        expect(inTransaction).toBe(false);
        return f.vault.tombstone(...args);
      },
    },
  });
  f.setNow(first.expiresAt! + 1);
  await assets.maintain();
  expect(retirements).toEqual([true]);
  expect((await assets.status('o')).state).toBe('missing');
});
