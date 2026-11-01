import { afterEach, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createDatabase } from './helpers/database';
import { JobsActions } from '../packages/core/src/signing/jobs-actions';
import { ReceiveUpload } from '../packages/core/src/application/receive-upload';
import { PersonalObjects, PersonalStorage } from '../packages/core/src/library/personal-storage';
import { handleLibrary } from '../server/http/library';
import type { AuthenticatedContext } from '../server/http/context';
const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});
it('admits the owner slot before transferring any file and binds bytes to that job', async () => {
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
  const dir = await mkdtemp(path.join(tmpdir(), 'isign-admission-'));
  dirs.push(dir);
  const objects = new PersonalObjects(db, dir, () => 1000, {
    maxFile: 1024,
    ownerQuota: 8192,
    globalQuota: 16384,
    minimumFree: 0,
    retentionMs: 86400000,
  });
  await objects.recover();
  const jobs = new JobsActions(db, () => 1000),
    storage = new PersonalStorage(objects);
  const receiveUpload = new ReceiveUpload(db, storage, jobs);
  const app = {
    jobs,
    receiveUpload: receiveUpload.run.bind(receiveUpload),
    capabilities: { runner: true },
  };
  const context = (request: NextRequest, target: string) =>
    ({
      request,
      target,
      app,
      owner: 'o',
      raw: '',
      csrf: '',
      session: { ownerId: 'o', verifiedAt: 1000 },
      requireUpload: async () => {},
      uploadAllowed: async () => true,
    }) as unknown as AuthenticatedContext;
  const admitted = await handleLibrary(
    context(
      new NextRequest('http://127.0.0.1:3000/api/uploads', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'App.ipa', key: 'key', deviceId: 'd' }),
      }),
      'uploads',
    ),
  );
  expect(admitted?.status).toBe(201);
  const job = (await admitted!.json()) as { jobId: string; uploadId: string };
  expect((await db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'receiving' }]);
  const transferred = await handleLibrary(
    context(
      new NextRequest('http://127.0.0.1:3000/api/uploads/' + job.uploadId, {
        method: 'PUT',
        body: 'source',
      }),
      'uploads/' + job.uploadId,
    ),
  );
  expect(transferred?.status).toBe(201);
  expect((await db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'queued' }]);
  expect((await db.query('SELECT size FROM uploads')).rows).toEqual([{ size: 6 }]);
});
