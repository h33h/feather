import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { QueuedDispatcher } from '../packages/core/src/signing/queued-dispatcher';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';
async function fixture() {
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1)");
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,connection_generation,enrollment_verified_at) VALUES('d','o','c','o','Phone','ready',1,1)",
  );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','App.ipa','u.ipa',1,'digest','ready',1,999999)",
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_owner_id,connection_generation,state,idempotency_key,created_at,updated_at) VALUES('j','o','u','d','c','o',1,'queued','key',1,1)",
  );
  return db;
}
it('never changes a scheduled automatic retry into a permanent start failure', async () => {
  const db = await fixture();
  const queue = new JobLifecycle(db, () => 1000);
  const dispatcher = new QueuedDispatcher(
    db,
    () => 1000,
    async () => {
      const lease = await queue.claim('j', 'o');
      await queue.finishAttempt(
        { ownerId: 'o', jobId: 'j', leaseToken: lease },
        { code: 'PROVIDER_TIMEOUT' },
      );
      throw new Error('temporary failure');
    },
  );
  await dispatcher.trigger('o', 'j');
  await dispatcher.drain();
  expect((await db.query('SELECT state,attempts FROM jobs')).rows).toEqual([
    { state: 'queued', attempts: 1 },
  ]);
});
it('finishes unusable queued input and schedules source cleanup instead of waiting for user consent', async () => {
  const db = await fixture();
  await db.query("UPDATE uploads SET expires_at=1 WHERE id='u'");
  const dispatcher = new QueuedDispatcher(
    db,
    () => 1000,
    async () => {},
  );
  await dispatcher.dispatch();
  await dispatcher.drain();
  expect((await db.query('SELECT state,reason FROM jobs')).rows).toEqual([
    { state: 'failed', reason: 'SOURCE_EXPIRED' },
  ]);
  expect((await db.query('SELECT delete_requested_at FROM uploads')).rows).toEqual([
    { delete_requested_at: 1000 },
  ]);
});
it('an incoming request wakes the oldest job rather than jumping the queue', async () => {
  const db = await fixture();
  try {
    const calls: string[] = [];
    const dispatcher = new QueuedDispatcher(
      db,
      () => 1000,
      async (_owner, job) => {
        calls.push(job);
      },
    );
    await dispatcher.trigger('different-owner', 'newer-job');
    await dispatcher.drain();
    expect(calls).toEqual(['j']);
  } finally {
    await db.close();
  }
});
