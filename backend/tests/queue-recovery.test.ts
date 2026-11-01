import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';

async function fixture() {
  const db = await createDatabase();
  for (const owner of ['one', 'two']) {
    await db.query('INSERT INTO users(id,login_name,created_at) VALUES($1,$1,1)', [owner]);
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES($1,$2,$1,'ready','asc')",
      ['c-' + owner, owner],
    );
    await db.query(
      'INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES($1,$2,$1)',
      [owner, 'c-' + owner],
    );
    await db.query(
      "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,selected,connection_generation,enrollment_verified_at,udid,apple_resource_id) VALUES($1,$2,$3,$2,'Phone','ready',true,1,1,$4,'apple-device')",
      ['d-' + owner, owner, 'c-' + owner, 'a'.repeat(40)],
    );
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES($1,$2,'App.ipa',$1,1,$3,'ready',1,99999999)",
      ['u-' + owner, owner, 'a'.repeat(64)],
    );
    await db.query(
      "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_owner_id,connection_generation,state,idempotency_key,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$2,1,'queued',$1,1,1)",
      ['j-' + owner, owner, 'u-' + owner, 'd-' + owner, 'c-' + owner],
    );
  }
  let now = 1000;
  const queue = new JobLifecycle(db, () => now);
  return {
    db,
    queue,
    setNow(value: number) {
      now = value;
    },
  };
}
it('allows only one global worker claim even for different owners', async () => {
  const { db, queue } = await fixture();
  await queue.claim('j-one', 'one');
  await expect(queue.claim('j-two', 'two')).rejects.toThrow('RUNNER_BUSY');
  expect((await db.query("SELECT id FROM jobs WHERE state='analyzing'")).rows).toEqual([
    { id: 'j-one' },
  ]);
});
it('uses the same single retry budget across worker restarts and fences the old lease', async () => {
  const { db, queue, setNow } = await fixture();
  const first = await queue.claim('j-one', 'one');
  setNow(61001);
  await queue.recoverLeases();
  await expect(queue.heartbeat('j-one', 'one', first)).rejects.toThrow('LEASE_LOST');
  setNow(66001);
  const second = await queue.claim('j-one', 'one');
  expect(second).not.toBe(first);
  setNow(126002);
  await queue.recoverLeases();
  expect((await db.query("SELECT state,attempts FROM jobs WHERE id='j-one'")).rows).toEqual([
    { state: 'failed', attempts: 2 },
  ]);
  await expect(queue.claim('j-one', 'one')).rejects.toThrow('NOT_CLAIMABLE');
});
it('does not resume a job whose source was deleted or whose access was revoked', async () => {
  const { db, queue, setNow } = await fixture();
  await queue.claim('j-one', 'one');
  await db.query("UPDATE uploads SET status='expired',delete_requested_at=2 WHERE id='u-one'");
  setNow(61001);
  await queue.recoverLeases();
  expect((await db.query("SELECT state FROM jobs WHERE id='j-one'")).rows).toEqual([
    { state: 'failed' },
  ]);
});

it('keeps the source for the only automatic retry and schedules deletion after a terminal error', async () => {
  const { db, queue, setNow } = await fixture();
  const lease = await queue.claim('j-one', 'one');
  expect(
    await queue.finishAttempt(
      { ownerId: 'one', jobId: 'j-one', leaseToken: lease },
      { code: 'PROVIDER_TIMEOUT' },
    ),
  ).toEqual({ state: 'queued' });
  expect((await db.query("SELECT delete_requested_at FROM uploads WHERE id='u-one'")).rows).toEqual(
    [{ delete_requested_at: null }],
  );
  setNow(6000);
  const second = await queue.claim('j-one', 'one');
  expect(
    await queue.finishAttempt(
      { ownerId: 'one', jobId: 'j-one', leaseToken: second },
      { code: 'INVALID_P8' },
    ),
  ).toEqual({ state: 'failed' });
  expect((await db.query("SELECT delete_requested_at FROM uploads WHERE id='u-one'")).rows).toEqual(
    [{ delete_requested_at: 6000 }],
  );
});

it('reserves receiving before transfer and binds request replay to its original device and name', async () => {
  const { db, queue } = await fixture();
  await db.query("DELETE FROM jobs WHERE owner_id='one'");
  const input = { key: 'receiving', deviceId: 'd-one', name: 'New.ipa', source: 'upload' as const };
  const first = await queue.beginSubmission('one', input);
  expect(await queue.beginSubmission('one', input)).toEqual(first);
  await expect(queue.beginSubmission('one', { ...input, name: 'Other.ipa' })).rejects.toThrow(
    'IDEMPOTENCY_BINDING_MISMATCH',
  );
  await expect(queue.beginSubmission('one', { ...input, key: 'other' })).rejects.toThrow(
    'ACTIVE_JOB_EXISTS',
  );
  await queue.failReceiving('one', first.jobId, 'UPLOAD_INTERRUPTED');
  expect(
    (await db.query('SELECT delete_requested_at FROM uploads WHERE id=$1', [first.uploadId])).rows,
  ).toEqual([{ delete_requested_at: 1000 }]);
});

it('rejects replay after the same device was rebound to a new connection generation', async () => {
  const { db, queue } = await fixture();
  await db.query("DELETE FROM jobs WHERE owner_id='one'");
  const input = { key: 'bound', deviceId: 'd-one', name: 'New.ipa', source: 'upload' as const };
  await queue.beginSubmission('one', input);
  await db.query("UPDATE connections SET generation=2 WHERE id='c-one'");
  await db.query("UPDATE devices SET connection_generation=2 WHERE id='d-one'");
  await expect(queue.beginSubmission('one', input)).rejects.toThrow('IDEMPOTENCY_BINDING_MISMATCH');
});

it('keeps replay stable when server provenance is enriched after accepting the request', async () => {
  const { db, queue } = await fixture();
  await db.query("DELETE FROM jobs WHERE owner_id='one'");
  const input = {
    key: 'catalog',
    deviceId: 'd-one',
    name: 'Catalog.ipa',
    source: 'catalog' as const,
    provenance: { sourceId: 'source', releaseId: 'release', snapshot: 'snapshot' },
  };
  const first = await queue.beginSubmission('one', input);
  await db.query(
    'UPDATE uploads SET provenance=provenance||\'{"receivedAt":1234}\'::jsonb WHERE id=$1',
    [first.uploadId],
  );
  expect(await queue.beginSubmission('one', input)).toEqual(first);
});

it('keeps the global worker fenced until the interrupted executor is confirmed destroyed', async () => {
  const { db, queue, setNow } = await fixture();
  const lease = await queue.claim('j-one', 'one');
  const binding = {
    ownerId: 'one',
    jobId: 'j-one',
    leaseToken: lease,
    connectionId: 'c-one',
    connectionGeneration: 1,
    deviceId: 'd-one',
    uploadDigest: 'a'.repeat(64),
    taskNonce: 'nonce',
    isolationInstanceId: 'vm-one',
    expiresAt: 999999,
  };
  await db.query(
    "INSERT INTO executor_tasks(nonce,owner_id,job_id,binding,expires_at) VALUES('nonce','one','j-one',$1,999999)",
    [JSON.stringify(binding)],
  );
  setNow(61001);
  await queue.recoverLeases(async () => {
    throw new Error('cleanup unavailable');
  });
  await expect(queue.claim('j-two', 'two')).rejects.toThrow('RUNNER_BUSY');
  await queue.recoverLeases(async () => {});
  expect((await db.query("SELECT state FROM jobs WHERE id='j-one'")).rows).toEqual([
    { state: 'queued' },
  ]);
});
it('fences a launch whose HTTP response was lost before any executor task existed', async () => {
  const { db, queue, setNow } = await fixture();
  await queue.claim('j-one', 'one');
  setNow(61001);
  let retired = 0;
  await queue.recoverLeases(undefined, async () => {
    retired++;
    throw Error('retirement pending');
  });
  expect(retired).toBe(1);
  expect((await db.query("SELECT state FROM jobs WHERE id='j-one'")).rows).toEqual([
    { state: 'analyzing' },
  ]);
  await queue.recoverLeases(undefined, async () => {});
  expect((await db.query("SELECT state FROM jobs WHERE id='j-one'")).rows).toEqual([
    { state: 'queued' },
  ]);
});
it('worker capacity contention defers without consuming the signing retry', async () => {
  const { db, queue } = await fixture();
  const lease = await queue.claim('j-one', 'one');
  await queue.deferBusy({ ownerId: 'one', jobId: 'j-one', leaseToken: lease });
  expect((await db.query("SELECT state,attempts FROM jobs WHERE id='j-one'")).rows).toEqual([
    { state: 'queued', attempts: 0 },
  ]);
  expect((await db.query("SELECT delete_requested_at FROM uploads WHERE id='u-one'")).rows).toEqual(
    [{ delete_requested_at: null }],
  );
});
it('uses confirmed nonce retirement after broker restart without requiring its obsolete instance ID', async () => {
  const { db, queue, setNow } = await fixture();
  const lease = await queue.claim('j-one', 'one');
  await db.query(
    "INSERT INTO executor_tasks(nonce,owner_id,job_id,binding,expires_at) VALUES('task','one','j-one',$1,999999)",
    [
      JSON.stringify({
        ownerId: 'one',
        jobId: 'j-one',
        leaseToken: lease,
        isolationInstanceId: 'old-instance',
      }),
    ],
  );
  setNow(61001);
  await queue.recoverLeases(
    async () => {
      throw Error('instance disappeared after confirmed broker recovery');
    },
    async () => {},
  );
  expect((await db.query("SELECT state FROM jobs WHERE id='j-one'")).rows).toEqual([
    { state: 'queued' },
  ]);
});
