import { afterEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { createRunnerAuthorizer } from '../packages/core/src/application/request-runner-authorization';
import type { Database } from '../packages/core/src/shared/database';
import type { HttpApplication } from '../server/http/application';
vi.mock('../server/runtime', () => ({ origin: 'https://runner.invalid' }));
import { handleRunner } from '../server/http/runner';
afterEach(() => vi.unstubAllEnvs());
function context(proof?: string, authorization = 'Bearer runner-token') {
  vi.stubEnv('ISIGN_RUNNER_TOKEN', 'runner-token');
  vi.stubEnv('ISIGN_RUNNER_PROOF_KEY', proof);
  const runnerAuthorization = createRunnerAuthorizer({} as Database, () => 1000, 'audience', proof);
  return {
    request: new NextRequest('https://runner.invalid/api/internal/runner/authorize', {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({
        operation: 'capabilities',
        binding: { nonce: 'n'.repeat(43) },
        nonce: 'r'.repeat(43),
        audience: 'audience',
      }),
    }),
    target: 'internal/runner/authorize',
    app: { runnerAuthorization } as HttpApplication,
    raw: '',
    csrf: '',
  };
}
it.each([undefined, 'invalid', 'a'.repeat(63)])(
  'denies unavailable proof configuration with the original error (%s)',
  async (proof) => {
    await expect(handleRunner(context(proof))).rejects.toMatchObject({
      code: 'RUNNER_AUTHORIZATION_DENIED',
      status: 403,
    });
  },
);
it('delegates a valid authenticated request to the composed authorizer', async () => {
  const result = await handleRunner(context('a'.repeat(64)));
  expect(result?.status).toBe(200);
  expect(await result?.json()).toMatchObject({
    report: { authorized: true, operation: 'authorize-binding', audience: 'audience' },
  });
});
it('rejects bearer credentials before application authorization', async () => {
  await expect(handleRunner(context('a'.repeat(64), 'Bearer wrong'))).rejects.toMatchObject({
    code: 'RUNNER_AUTHORIZATION_DENIED',
    status: 403,
  });
});
