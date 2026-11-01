import { expect, it, vi } from 'vitest';
import { ReceiveUpload } from '../packages/core/src/application/receive-upload';
import { Failure } from '../packages/core/src/shared/errors';
import type { QueryDatabase } from '../packages/core/src/shared/database';
const input = async function* () {
  yield Buffer.from('ipa');
};
function fixture(available = true) {
  const query = vi.fn(async (_sql: string, _params?: unknown[]) => ({
    rows: available ? [{ id: 'job', name: 'App.ipa' }] : [],
  }));
  const upload = vi.fn(async () => ({ id: 'upload', size: 3, digest: 'digest' }));
  const completeSource = vi.fn(async () => ({ id: 'job' }));
  const failReceiving = vi.fn(async () => {});
  const useCase = new ReceiveUpload(
    { query } as unknown as QueryDatabase,
    { upload },
    { completeSource, failReceiving },
  );
  return { useCase, query, upload, completeSource, failReceiving };
}
it('receives the owner-bound source and completes only after storage', async () => {
  const f = fixture();
  const signal = new AbortController().signal;
  await expect(f.useCase.run('owner', 'upload', input(), signal)).resolves.toEqual({
    upload: { id: 'upload', size: 3, digest: 'digest' },
    jobId: 'job',
  });
  expect(f.query.mock.calls[0][1]).toEqual(['owner', 'upload']);
  expect(f.upload).toHaveBeenCalledWith('owner', 'App.ipa', expect.anything(), {
    uploadId: 'upload',
    jobId: 'job',
    signal,
  });
  expect(f.upload.mock.invocationCallOrder[0]).toBeLessThan(
    f.completeSource.mock.invocationCallOrder[0],
  );
  expect(f.failReceiving).not.toHaveBeenCalled();
});
it('rejects cancelled or foreign-owner sources before storing', async () => {
  const f = fixture(false);
  await expect(f.useCase.run('foreign', 'upload', input())).rejects.toThrow(
    'SOURCE_RECEIVE_UNAVAILABLE',
  );
  expect(f.upload).not.toHaveBeenCalled();
  expect(f.failReceiving).not.toHaveBeenCalled();
});
it.each([new Error('stream stopped'), new Failure('JOB_CANCELLED', 409)])(
  'fences interrupted and cancelled receives with the original failure code',
  async (error) => {
    const f = fixture();
    f.upload.mockRejectedValueOnce(error);
    await expect(f.useCase.run('owner', 'upload', input())).rejects.toBe(error);
    expect(f.completeSource).not.toHaveBeenCalled();
    expect(f.failReceiving).toHaveBeenCalledWith(
      'owner',
      'job',
      error instanceof Failure ? error.code : 'UPLOAD_INTERRUPTED',
    );
  },
);
it('fences a completion failure after storage without swallowing it', async () => {
  const f = fixture();
  const error = new Failure('SUBMISSION_CHANGED', 409);
  f.completeSource.mockRejectedValueOnce(error);
  await expect(f.useCase.run('owner', 'upload', input())).rejects.toBe(error);
  expect(f.failReceiving).toHaveBeenCalledWith('owner', 'job', 'SUBMISSION_CHANGED');
});
