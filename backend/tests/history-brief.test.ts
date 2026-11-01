import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { cleanupHistory } from '../packages/core/src/library/installation-history';
it('keeps terminal display metadata after source deletion and expires history after thirty days', async () => {
  const db = await createDatabase();
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1),('foreign','foreign',1)",
  );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at,delete_requested_at) VALUES('u','o','App.ipa','u.ipa',6,'digest','expired',1,1,1)",
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,state,reason,idempotency_key,created_at,updated_at,finished_at,display_snapshot) VALUES('j','o','u','failed','DRM_UNSUPPORTED','key',1,1000,1000,'{\"name\":\"App\",\"version\":\"1.0\"}')",
  );
  expect((await db.query("SELECT display_snapshot FROM jobs WHERE id='j'")).rows).toEqual([
    { display_snapshot: { name: 'App', version: '1.0' } },
  ]);
  await cleanupHistory(db, 1000 + 2592000000 - 1);
  expect((await db.query('SELECT id FROM jobs')).rows).toEqual([{ id: 'j' }]);
  await cleanupHistory(db, 1000 + 2592000000);
  expect((await db.query('SELECT id FROM jobs')).rows).toHaveLength(0);
  expect((await db.query('SELECT id FROM uploads')).rows).toHaveLength(0);
});
