import { timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { origin } from '../runtime';
import { Failure, hash } from '../../packages/core/src/shared/index';
import { body, response } from './common';
import type { PublicContext } from './context';
export async function handleRunner(context: PublicContext) {
  const { request, target, app } = context;
  if (target === 'internal/runner/authorize' && request.method === 'POST') {
    if (new URL(origin).protocol !== 'https:')
      throw new Failure('RUNNER_AUTHORIZATION_UNAVAILABLE', 503);
    const supplied = request.headers.get('authorization') ?? '';
    const expected = process.env.ISIGN_RUNNER_TOKEN;
    const proof = process.env.ISIGN_RUNNER_PROOF_KEY;
    if (
      !app.runnerAuthorization ||
      !expected ||
      !proof ||
      !/^[a-f0-9]{64}$/.test(proof) ||
      supplied.length > 1024 ||
      !timingSafeEqual(
        Buffer.from(hash(supplied), 'hex'),
        Buffer.from(hash('Bearer ' + expected), 'hex'),
      )
    )
      throw new Failure('RUNNER_AUTHORIZATION_DENIED', 403);
    const data = z
      .object({
        operation: z.string().max(64),
        binding: z.record(z.string(), z.unknown()),
        nonce: z.string().length(43),
        audience: z.string().max(100),
      })
      .parse(await body(request, 16384));
    return response(await app.runnerAuthorization.authorize(data));
  }
}
