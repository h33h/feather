import { expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { createDatabase } from './helpers/database';
import { connectionFixture, deviceFixture, loginFixture } from './helpers/login';
import { cleanupHistory } from '../packages/core/src/library/installation-history';

it('removes legacy import foreign keys before upgrading while preserving current account and installation data', async () => {
  const db = await createDatabase();
  const user = await loginFixture(db, 'upgrade', 1000);
  const connection = await connectionFixture(db, user.ownerId, 'TEAM');
  const device = await deviceFixture(db, user.ownerId, connection.id, 'Phone', '18.0');
  await db.exec(`
    ALTER TABLE uploads ADD COLUMN provenance jsonb;
    CREATE TABLE imports (upload_id text REFERENCES uploads(id));
    CREATE TABLE selections (owner_id text REFERENCES users(id));
  `);
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('legacy-upload',$1,'Client.ipa','legacy.ipa',1,'digest','expired',1,1)",
    [user.ownerId],
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,state,idempotency_key,created_at,updated_at,finished_at) VALUES('legacy-job',$1,'legacy-upload','failed','key',1,1000,1000)",
    [user.ownerId],
  );
  await db.query("INSERT INTO imports VALUES('legacy-upload')");
  await db.query('INSERT INTO selections VALUES($1)', [user.ownerId]);
  await expect(cleanupHistory(db, 1000 + 2592000000)).rejects.toMatchObject({ code: '23503' });
  await db.exec(await readFile('backend/packages/db/client-installer-upgrade.sql', 'utf8'));
  expect((await db.query('SELECT id FROM jobs')).rows).toEqual([{ id: 'legacy-job' }]);
  expect((await db.query('SELECT id FROM devices')).rows).toEqual([{ id: device.id }]);
  expect((await db.query('SELECT id FROM connections')).rows).toEqual([{ id: connection.id }]);
  expect((await db.query('SELECT id FROM users')).rows).toEqual([{ id: user.ownerId }]);
  await cleanupHistory(db, 1000 + 2592000000);
  expect((await db.query('SELECT id FROM jobs')).rows).toEqual([]);
  expect((await db.query('SELECT id FROM uploads')).rows).toEqual([]);
  // Re-running the explicit operator step is safe.
  await db.exec(await readFile('backend/packages/db/client-installer-upgrade.sql', 'utf8'));
});
