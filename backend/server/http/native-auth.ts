import { z } from 'zod';
import { Failure } from '../../packages/core/src/shared/index';
import type { PublicContext } from './context';
import { body, response } from './common';
import { origin } from '../runtime';
const startInput = z.object({
  state: z.string().max(512),
  codeChallenge: z.string().max(128),
  redirectUri: z.string().max(256),
});
export function nativeBearer(request: PublicContext['request']) {
  const match = /^Bearer ([A-Za-z0-9_-]+)$/i.exec(request.headers.get('authorization') ?? '');
  if (!match) throw new Failure('UNAUTHENTICATED', 401);
  return match[1];
}
/** Runs before the web cookie/Origin gate. Never reads a cookie for native authorization. */
export async function handleNativeAuth({ request, target, app }: PublicContext) {
  if (!target.startsWith('native/v1/')) return null;
  const native = app.nativeSessions;
  if (
    request.method === 'POST' &&
    ['native/v1/auth/start', 'native/v1/auth/exchange', 'native/v1/auth/refresh'].includes(
      target,
    ) &&
    app.auth
  ) {
    await app.auth.rate('native:global');
    await app.auth.rate(
      'native:ip:' + (request.headers.get('x-real-ip') ?? 'unknown').slice(0, 64),
    );
  }
  if (request.method === 'POST') {
    if (target === 'native/v1/auth/start')
      return response(await native.start(startInput.parse(await body(request, 4096))));
    if (target === 'native/v1/auth/exchange')
      return response(
        await native.exchange(
          z
            .object({
              transactionId: z.string().max(128),
              code: z.string().max(128),
              codeVerifier: z.string().max(128),
              redirectUri: z.string().max(256),
            })
            .parse(await body(request, 4096)),
        ),
      );
    if (target === 'native/v1/auth/refresh')
      return response(
        await native.refresh(
          z.object({ refreshToken: z.string().max(128) }).parse(await body(request, 4096))
            .refreshToken,
        ),
      );
    if (target === 'native/v1/auth/step-up') {
      const principal = await native.authorize(nativeBearer(request));
      return response(
        await native.start({
          ...startInput.parse(await body(request, 4096)),
          sessionId: principal.sessionId,
        }),
      );
    }
    if (target === 'native/v1/auth/logout') {
      await native.logout(nativeBearer(request));
      return response({ ok: true, authenticated: false });
    }
  }
  if (target === 'native/v1/session' && request.method === 'GET')
    return response(await native.authorize(nativeBearer(request)));
  return null;
}
/** Browser completion keeps the existing web CSRF and Origin contract. */
export async function handleNativeCompletion({ request, target, app, raw, csrf }: PublicContext) {
  if (target !== 'auth/native/complete' || request.method !== 'POST') return null;
  await app.sessions.authorizeWrite(raw, csrf, request.headers.get('origin') ?? '', origin);
  const { transactionId } = z
    .object({ transactionId: z.string().max(128) })
    .parse(await body(request, 4096));
  return response(await app.nativeSessions.complete(transactionId, raw));
}
