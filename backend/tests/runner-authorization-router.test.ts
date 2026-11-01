import { afterEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { createHmac } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { RunnerAuthorization } from '../packages/core/src/signing/runner-authorization';
import { canonicalReport } from '../packages/core/src/shared/canonical-json';

const { runtime } = vi.hoisted(() => ({ runtime: vi.fn() }));
vi.mock('../server/runtime', () => ({ origin: 'https://isign.example.test', runtime }));
import { handle } from '../server/http/router';

afterEach(() => vi.unstubAllEnvs());
it('allows the private broker to obtain signed capabilities and rejects an invalid bearer', async () => {
  const db = await createDatabase(),
    key = Buffer.alloc(32, 8),
    token = 't'.repeat(43);
  vi.stubEnv('ISIGN_RUNNER_TOKEN', token);
  vi.stubEnv('ISIGN_RUNNER_PROOF_KEY', key.toString('hex'));
  runtime.mockResolvedValue({
    runnerAuthorization: new RunnerAuthorization(db, () => 1000, 'test', key),
  });
  const request = (bearer: string) =>
    new NextRequest('https://isign.example.test/api/internal/runner/authorize', {
      method: 'POST',
      headers: {
        host: 'isign.example.test',
        authorization: 'Bearer ' + bearer,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        operation: 'capabilities',
        binding: { nonce: 'a'.repeat(43) },
        nonce: 'b'.repeat(43),
        audience: 'test',
      }),
    });
  const response = await handle(request(token));
  expect(response.status).toBe(200);
  const result = await response.json();
  expect(result.report).toMatchObject({ authorized: true, audience: 'test' });
  expect(result.attestation).toBe(
    createHmac('sha256', key).update(canonicalReport(result.report)).digest('hex'),
  );
  const denied = await handle(request('wrong'));
  expect(denied.status).toBe(403);
  expect(await denied.json()).toMatchObject({ code: 'RUNNER_AUTHORIZATION_DENIED' });
});
