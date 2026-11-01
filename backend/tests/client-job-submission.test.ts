import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { connectionFixture, deviceFixture, loginFixture } from './helpers/login';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';

async function fixture() {
  const db = await createDatabase();
  const owner = (await loginFixture(db, 'client-queue', 1000)).ownerId;
  const connection = await connectionFixture(db, owner, 'TEAM');
  const device = await deviceFixture(db, owner, connection.id, 'Phone', '18.0');
  return { db, owner, device, jobs: new JobLifecycle(db, () => 1000) };
}

it('reserves the published client digest before receiving bytes and replays one durable job', async () => {
  const f = await fixture();
  const input = {
    key: 'install',
    deviceId: f.device.id,
    releaseSha256: 'a'.repeat(64),
    version: '2.0',
  };
  const result = await f.jobs.beginClientInstallation(f.owner, input);
  expect(await f.jobs.beginClientInstallation(f.owner, input)).toEqual(result);
  expect((await f.db.query('SELECT name,digest,status FROM uploads')).rows).toEqual([
    { name: 'iSign Client.ipa', digest: 'a'.repeat(64), status: 'receiving' },
  ]);
  expect((await f.db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'receiving' }]);
  await expect(
    f.jobs.beginClientInstallation(f.owner, { ...input, releaseSha256: 'b'.repeat(64) }),
  ).rejects.toThrow('IDEMPOTENCY_BINDING_MISMATCH');
  await expect(
    f.jobs.beginClientInstallation(f.owner, { ...input, key: 'another' }),
  ).rejects.toThrow('ACTIVE_JOB_EXISTS');
});

it('rejects a missing device or malformed published digest before reserving a source', async () => {
  const f = await fixture();
  for (const input of [
    { key: 'install', deviceId: '', releaseSha256: 'a'.repeat(64) },
    { key: 'install', deviceId: f.device.id, releaseSha256: 'arbitrary-source' },
  ])
    await expect(f.jobs.beginClientInstallation(f.owner, input)).rejects.toThrow('INVALID_REQUEST');
  expect((await f.db.query('SELECT id FROM uploads')).rows).toEqual([]);
});
