import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { JobsActions } from '../packages/core/src/signing/jobs-actions';
async function fixture() {
  const db = await createDatabase();
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1),('foreign','foreign',1)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
  );
  for (const device of ['d', 'other'])
    await db.query(
      "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,selected,connection_generation,enrollment_verified_at) VALUES($1,'o','c','o',$1,'ready',$2,1,1)",
      [device, device === 'd'],
    );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','App.ipa','u.ipa',1,'digest','ready',1,999999)",
  );
  return db;
}
it('queues immediately without a confirmation or consent roundtrip', async () => {
  const db = await fixture();
  const actions = new JobsActions(db, () => 1000);
  expect(await actions.ensure('o', { uploadId: 'u', deviceId: 'd', key: 'key' })).toMatchObject({
    state: 'queued',
    reason: null,
  });
  expect((await db.query('SELECT connection_owner_id FROM jobs')).rows).toEqual([
    { connection_owner_id: 'o' },
  ]);
});
it('rejects replay with a different target device', async () => {
  const db = await fixture();
  const actions = new JobsActions(db, () => 1000);
  await actions.ensure('o', { uploadId: 'u', deviceId: 'd', key: 'key' });
  await expect(
    actions.ensure('o', { uploadId: 'u', deviceId: 'other', key: 'key' }),
  ).rejects.toThrow('IDEMPOTENCY_BINDING_MISMATCH');
});
it('cancellation fences the lease and task and requests physical source cleanup', async () => {
  const db = await fixture();
  const actions = new JobsActions(db, () => 1000);
  const job = await actions.ensure('o', { uploadId: 'u', deviceId: 'd', key: 'key' });
  await db.query(
    "UPDATE jobs SET state='signing',lease_token='lease',lease_expires=2000 WHERE id=$1",
    [job.id],
  );
  await db.query(
    "INSERT INTO executor_tasks(nonce,owner_id,job_id,binding,expires_at) VALUES('nonce','o',$1,'{}',2000)",
    [job.id],
  );
  expect(await actions.cancel('o', job.id)).toMatchObject({ state: 'cancelled' });
  expect((await db.query('SELECT lease_token,finished_at FROM jobs')).rows).toEqual([
    { lease_token: null, finished_at: 1000 },
  ]);
  expect((await db.query('SELECT consumed FROM executor_tasks')).rows).toEqual([
    { consumed: true },
  ]);
  expect((await db.query('SELECT delete_requested_at FROM uploads')).rows).toEqual([
    { delete_requested_at: 1000 },
  ]);
  await expect(actions.retry('o', job.id)).rejects.toThrow('SOURCE_RELOAD_REQUIRED');
});
it('does not let another active user cancel or read a private job', async () => {
  const db = await fixture();
  const actions = new JobsActions(db, () => 1000);
  const job = await actions.ensure('o', { uploadId: 'u', deviceId: 'd', key: 'key' });
  await expect(actions.cancel('foreign', job.id)).rejects.toThrow('NOT_FOUND');
  expect((await db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'queued' }]);
});
