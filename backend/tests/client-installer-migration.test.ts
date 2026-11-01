import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { loginFixture } from './helpers/login';
import { migrateClientInstaller } from '../packages/core/src/infrastructure/client-installer-migrations';
it('adds durable client installation mapping without native tables and checks recorded migration bytes', async () => {
  const db = await createDatabase(),
    user = await loginFixture(db, 'admin', 1000);
  await db.query("UPDATE users SET role='admin'");
  await db.query('DROP TABLE client_installations');
  await db.query(
    'DROP TABLE native_auth_transactions,native_refresh_tokens,native_sessions,feather_profile_operations,feather_signing_identities CASCADE',
  );
  expect(await migrateClientInstaller(db)).toEqual({ applied: ['20261101-client-installer.sql'] });
  expect(await migrateClientInstaller(db)).toEqual({ applied: [] });
  expect((await db.query('SELECT id FROM users')).rows).toEqual([{ id: user.ownerId }]);
  await db.query("UPDATE isign_schema_migrations SET sha256='changed'");
  await expect(migrateClientInstaller(db)).rejects.toThrow('MIGRATION_CHECKSUM_MISMATCH');
});
