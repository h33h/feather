import { expect, it, vi } from 'vitest';
import { RequestLifecycle } from '../packages/core/src/application/request-lifecycle';
import { ReceiveDeviceCallback } from '../packages/core/src/application/receive-device-callback';
import { createRunnerAuthorizer } from '../packages/core/src/application/request-runner-authorization';
import { Failure } from '../packages/core/src/shared/errors';
import type { Database } from '../packages/core/src/shared/database';
it('deletes the native account before storage and artifact cleanup', async () => {
  const events: string[] = [];
  const lifecycle = new RequestLifecycle(
    {
      removeProfile: async (owner: string) => {
        expect(owner).toBe('owner');
        events.push('account');
      },
    },
    {
      cleanup: async () => {
        events.push('storage');
      },
    },
    {
      cleanup: async () => {
        events.push('artifacts');
      },
    },
  );
  await lifecycle.deleteAccountFor('owner');
  expect(events).toEqual(['account', 'storage', 'artifacts']);
});
it('captures only opted-in collection failures and preserves the callback error if diagnostics fail', async () => {
  const problem = new Failure('INVALID_DEVICE_CALLBACK');
  const capture = vi.fn(async () => {
    throw Error('disk unavailable');
  });
  const collections = {
    callback: async () => {
      throw problem;
    },
  };
  const packet = Buffer.from('cms');
  await expect(new ReceiveDeviceCallback(collections).run('challenge', packet)).rejects.toBe(
    problem,
  );
  expect(capture).not.toHaveBeenCalled();
  await expect(
    new ReceiveDeviceCallback(collections, { capture }).run('challenge', packet),
  ).rejects.toBe(problem);
  expect(capture).toHaveBeenCalledWith('challenge', packet, 'INVALID_DEVICE_CALLBACK');
});
it.each([undefined, '', 'not-hex', 'a'.repeat(63), 'a'.repeat(65)])(
  'disables runner authorization for absent or invalid proof configuration (%s)',
  (proof) => {
    const db = { query: vi.fn() } as unknown as Database;
    expect(createRunnerAuthorizer(db, Date.now, 'audience', proof)).toBeUndefined();
    expect(db.query).not.toHaveBeenCalled();
  },
);
it('constructs runner authorization only for a valid configured key', () => {
  expect(
    createRunnerAuthorizer({} as Database, Date.now, 'audience', 'a'.repeat(64)),
  ).toBeDefined();
});
it('keeps launch retirement available without signing kickoff and discards the retired attempt afterwards', async () => {
  const { SigningExecution } = await import('../packages/core/src/application/signing-execution');
  const events: string[] = [];
  const db = {
    query: async () => {
      events.push('lookup');
      return { rows: [{ owner_id: 'owner', id: 'job' }] };
    },
  } as unknown as Database;
  const artifacts = {
    reserveJob: vi.fn(),
    discardAttempt: async (owner: string, job: string) => {
      expect([owner, job]).toEqual(['owner', 'job']);
      events.push('discard');
    },
    cleanup: vi.fn(),
  };
  const execution = new SigningExecution(
    db,
    { objects: { free: vi.fn() }, cleanup: vi.fn() },
    artifacts,
    undefined,
    async (nonce) => {
      expect(nonce).toBe('lease');
      events.push('retire');
    },
  );
  await execution.retireLaunch('lease');
  expect(events).toEqual(['retire', 'lookup', 'discard']);
});
it('reserves the unchanged disk budget before kickoff and cleans artifacts before storage after completion', async () => {
  const { SigningExecution } = await import('../packages/core/src/application/signing-execution');
  const events: string[] = [];
  const db = { query: async () => ({ rows: [] }) } as unknown as Database;
  const execution = new SigningExecution(
    db,
    {
      objects: {
        free: async (bytes) => {
          expect(bytes).toBe(13 * 1024 ** 3);
          events.push('free');
        },
      },
      cleanup: async () => {
        events.push('storage');
      },
    },
    {
      reserveJob: async () => {
        events.push('reserve');
      },
      discardAttempt: async () => {
        events.push('discard');
      },
      cleanup: async () => {
        events.push('artifacts');
      },
    },
    async () => {
      events.push('kickoff');
      return 'result';
    },
  );
  await expect(execution.run('owner', 'job', 'device')).resolves.toBe('result');
  expect(events).toEqual(['free', 'reserve', 'kickoff', 'discard', 'artifacts', 'storage']);
});
