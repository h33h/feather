import { expect, it } from 'vitest';
import { createJobsFixture } from './job-fixtures';
import { JobRequests } from '../packages/core/src/application/job-requests';
import { JobsActions } from '../packages/core/src/signing/jobs-actions';
it('checks the selected registered device before creating the queue item', async () => {
  const db = await createJobsFixture();
  const actions = new JobsActions(db, () => 10);
  const requests = new JobRequests(db, actions, {
    checkRegistered: async (owner, device) => {
      if (owner !== 'o' || device !== 'd') throw Error('wrong device');
      throw Error('DEVICE_NOT_READY');
    },
  });
  await expect(requests.ensure('o', { uploadId: 'u', deviceId: 'd', key: 'one' })).rejects.toThrow(
    'DEVICE_NOT_READY',
  );
  expect((await db.query('SELECT id FROM jobs')).rows).toHaveLength(0);
});
it('creates an immediately queued request for the only eligible device', async () => {
  const db = await createJobsFixture();
  const actions = new JobsActions(db, () => 10);
  const requests = new JobRequests(db, actions);
  expect(await requests.ensure('o', { uploadId: 'u', key: 'one' })).toMatchObject({
    state: 'queued',
  });
});
