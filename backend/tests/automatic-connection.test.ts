import { expect, it } from 'vitest';
import { Failure } from '../packages/core/src/shared/errors';
it('automatically bootstraps missing signing material after adding a valid Apple key', async () => {
  const { connectAutomatically } = await import('../packages/core/src/apple/automatic-connection');
  const calls: string[] = [];
  const onboarding = {
    connect: async () => {
      calls.push('connect');
      throw new Failure('TEAM_PROOF_REQUIRED', 409);
    },
  };
  const result = await connectAutomatically(
    onboarding as never,
    async () => {
      calls.push('bootstrap');
      return { state: 'ready', teamId: 'TEAM123' };
    },
    'owner',
    {} as never,
  );
  expect(result).toEqual({ state: 'ready', teamId: 'TEAM123' });
  expect(calls).toEqual(['connect', 'bootstrap']);
});
it('does not create a certificate after invalid credentials or permission errors', async () => {
  const { connectAutomatically } = await import('../packages/core/src/apple/automatic-connection');
  let created = false;
  await expect(
    connectAutomatically(
      {
        connect: async () => {
          throw new Failure('INVALID_P8');
        },
      } as never,
      async () => {
        created = true;
        return {};
      },
      'owner',
      {} as never,
    ),
  ).rejects.toThrow('INVALID_P8');
  expect(created).toBe(false);
});
