import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { loginFixture } from './helpers/login';
import { migrateFeather } from '../packages/core/src/infrastructure/native-migrations';
import { createNativeAuth } from '../packages/core/src/composition/native-runtime';
import { SessionService } from '../packages/core/src/auth/sessions';
import { token } from '../packages/core/src/shared';
async function legacy() {
  const db = await createDatabase(),
    user = await loginFixture(db, 'migration-admin', 1000);
  await db.query("UPDATE users SET role='admin' WHERE id=$1", [user.ownerId]);
  await db.query(
    'DROP TABLE native_auth_transactions,native_refresh_tokens,native_sessions,feather_profile_operations,feather_signing_identities CASCADE',
  );
  return { db, user };
}
it('migrates an existing web database additively and is idempotent', async () => {
  const f = await legacy();
  const first = await migrateFeather(f.db);
  expect(first.applied).toHaveLength(3);
  expect(
    (
      await f.db.query(
        "SELECT column_name FROM information_schema.columns WHERE table_name='feather_signing_identities' AND column_name='replacement_for'",
      )
    ).rows,
  ).toHaveLength(1);
  expect((await new SessionService(f.db, { now: () => 1000 }).session(f.user.token)).ownerId).toBe(
    f.user.ownerId,
  );
  const native = await createNativeAuth(
    f.db,
    { ISIGN_FEATHER_ENABLED: 'true' },
    'https://isign.example.test',
  );
  await expect(
    native!.start({
      state: token(),
      codeChallenge: token(),
      redirectUri: 'isign-feather://auth/callback',
    }),
  ).resolves.toHaveProperty('transactionId');
  expect((await migrateFeather(f.db)).applied).toEqual([]);
  expect((await f.db.query('SELECT * FROM native_auth_transactions')).rows).toHaveLength(1);
});
it('disabled native integration leaves legacy cookie sessions usable without new tables', async () => {
  const f = await legacy();
  await expect(createNativeAuth(f.db, {}, 'https://isign.example.test')).resolves.toBeUndefined();
  await expect(
    createNativeAuth(f.db, { ISIGN_FEATHER_ENABLED: 'false' }, 'https://isign.example.test'),
  ).resolves.toBeUndefined();
  expect((await new SessionService(f.db, { now: () => 1000 }).session(f.user.token)).ownerId).toBe(
    f.user.ownerId,
  );
  await expect(
    createNativeAuth(f.db, { ISIGN_FEATHER_ENABLED: 'true' }, 'https://isign.example.test'),
  ).rejects.toThrow('DATABASE_UNINITIALIZED');
});
it('refuses partial native schema and changed migration checksums without dropping user data', async () => {
  const f = await legacy();
  await migrateFeather(f.db);
  await f.db.query("UPDATE isign_schema_migrations SET sha256='changed'");
  await expect(migrateFeather(f.db)).rejects.toThrow('MIGRATION_CHECKSUM_MISMATCH');
  expect((await f.db.query('SELECT id FROM users')).rows).toHaveLength(1);
  await f.db.query('DELETE FROM isign_schema_migrations');
  await f.db.query('DROP TABLE native_refresh_tokens');
  await expect(migrateFeather(f.db)).rejects.toThrow('DATABASE_MIGRATION_INCOMPLETE');
  expect((await f.db.query('SELECT * FROM sessions')).rows).toHaveLength(1);
});
