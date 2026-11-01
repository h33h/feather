import { afterEach, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { createDatabase } from './helpers/database';
import {
  PersonalObjects,
  PersonalStorage,
  PersonalArtifacts,
} from '../packages/core/src/library/personal-storage';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(
    directories.splice(0).map((file) => rm(file, { recursive: true, force: true })),
  );
});
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
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,selected,connection_generation,enrollment_verified_at) VALUES('d','o','c','o','Phone','ready',true,1,1)",
  );
  let now = 1000;
  const directory = await mkdtemp(path.join(tmpdir(), 'isign-source-test-'));
  directories.push(directory);
  const objects = new PersonalObjects(db, directory, () => now, {
    maxFile: 1024,
    ownerQuota: 8192,
    globalQuota: 16384,
    minimumFree: 0,
    retentionMs: 86400000,
  });
  await objects.recover();
  const queue = new JobLifecycle(db, () => now);
  const submission = await queue.beginSubmission('o', {
    name: 'App.ipa',
    source: 'upload',
    key: 'key',
    deviceId: 'd',
  });
  return {
    db,
    objects,
    queue,
    submission,
    storage: new PersonalStorage(objects),
    setNow(value: number) {
      now = value;
    },
  };
}
it('stores the source against the admitted job and removes it after terminal cleanup', async () => {
  const { db, storage, queue, submission } = await fixture();
  const upload = await storage.upload(
    'o',
    'App.ipa',
    Readable.from([Buffer.from('source')]),
    submission,
  );
  expect(upload.id).toBe(submission.uploadId);
  await queue.completeSource('o', submission.jobId);
  const lease = await queue.claim(submission.jobId, 'o');
  await queue.finishAttempt(
    { ownerId: 'o', jobId: submission.jobId, leaseToken: lease },
    { code: 'DRM_UNSUPPORTED' },
  );
  await expect(storage.read('o', submission.uploadId)).rejects.toThrow();
  await storage.cleanup();
  await expect(storage.read('o', submission.uploadId)).rejects.toThrow();
  expect((await db.query('SELECT state FROM personal_objects')).rows).toHaveLength(0);
});
it('retains the source during the single automatic retry even past the previous source retention period', async () => {
  const { storage, queue, submission, setNow } = await fixture();
  await storage.upload('o', 'App.ipa', Readable.from([Buffer.from('source')]), submission);
  await queue.completeSource('o', submission.jobId);
  const lease = await queue.claim(submission.jobId, 'o');
  await queue.finishAttempt(
    { ownerId: 'o', jobId: submission.jobId, leaseToken: lease },
    { code: 'PROVIDER_TIMEOUT' },
  );
  setNow(86401001);
  await storage.cleanup();
  const file = await storage.read('o', submission.uploadId);
  expect((await file.stat()).size).toBe(6);
  await file.close();
});
it('keeps verified bytes available after 29 minutes but denies them at 30 minutes', async () => {
  const { db, objects, submission, setNow } = await fixture();
  const artifacts = new PersonalArtifacts(objects);
  const key = '12345678-1234-1234-1234-123456789abc.ipa';
  const reservation = await objects.reserve('o', 'artifact', submission.jobId);
  await objects.write(reservation, 'o', 'artifact', key, Readable.from([Buffer.from('signed')]));
  await db.query("UPDATE jobs SET state='ready',finished_at=1000 WHERE id=$1", [submission.jobId]);
  await db.query(
    "INSERT INTO artifacts(id,owner_id,job_id,connection_id,connection_owner_id,device_id,object_key,digest,metadata,valid_until,created_at,ready_at,expires_at,verified) VALUES('a','o',$1,'c','o','d',$2,'digest','{\"generation\":1}',9999999,1000,1000,$3,true)",
    [submission.jobId, key, 1000 + artifacts.retentionMs],
  );
  setNow(1771000);
  const file = await artifacts.open(key);
  expect((await file.stat()).size).toBe(6);
  await file.close();
  setNow(1801000);
  await expect(artifacts.open(key)).rejects.toThrow('ARTIFACT_NOT_FOUND');
  expect((await db.query('SELECT id FROM personal_objects')).rows).toHaveLength(1);
});
it('confirmed executor retirement discards a crashed output before reserving the retry', async () => {
  const { db, objects, submission } = await fixture();
  const artifacts = new PersonalArtifacts(objects);
  const original = await artifacts.reserveJob('o', submission.jobId);
  const key = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa';
  await objects.write(original, 'o', 'artifact', key, Readable.from([Buffer.from('orphan')]));
  await artifacts.discardAttempt('o', submission.jobId);
  const next = await artifacts.reserveJob('o', submission.jobId);
  expect(next).not.toBe(original);
  expect((await db.query("SELECT state FROM personal_objects WHERE kind='artifact'")).rows).toEqual(
    [{ state: 'reserved' }],
  );
});
