import { presentApple } from './presenters';
import { z } from 'zod';
import { origin } from '../runtime';
import { Failure } from '../../packages/core/src/shared/index';
import { body, response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleApple(context: AuthenticatedContext) {
  const { request, target, app, raw, csrf, owner } = context;
  if (target === 'apple' && request.method === 'GET')
    return response(
      presentApple({ ...(await app.queries.apple(owner)), shares: await app.sharing.list(owner) }),
    );
  if (target === 'apple/connect' && request.method === 'POST') {
    if (!app.connectApple) throw new Failure('APPLE_ONBOARDING_UNAVAILABLE', 503);
    await app.sessions.fresh(raw, csrf, request.headers.get('origin') ?? '', origin);
    const data = z
      .object({
        filename: z.string().max(255),
        issuerId: z.string().max(64),
        keyId: z.string().max(20),
        keyType: z.literal('team').optional(),
        p8: z.string().max(16384),
      })
      .parse(await body(request));
    return response(
      await app.connectApple(owner, {
        ...data,
        p8: Buffer.from(data.p8),
      }),
    );
  }
  if (target === 'apple/bootstrap' && request.method === 'POST') {
    if (!app.bootstrap) throw new Failure('BOOTSTRAP_BROKER_UNAVAILABLE', 503);
    await app.sessions.fresh(raw, csrf, request.headers.get('origin') ?? '', origin);
    await body(request);
    return response(await app.bootstrap(owner));
  }
  if (target === 'apple/disconnect' && request.method === 'POST') {
    await app.connections.disconnect(raw, csrf, request.headers.get('origin') ?? '', origin);
    return response({ ok: true });
  }
}
