import type { RegistrationResponseJSON, AuthenticationResponseJSON } from '@simplewebauthn/server';
import { z } from 'zod';
import { origin } from '../runtime';
import { Failure } from '../../packages/core/src/shared/index';
import { body, response } from './common';
import type { PublicContext } from './context';
export async function handlePublicAuth(context: PublicContext) {
  const { request, target, app, raw, csrf } = context;
  if (target.startsWith('auth/passkey/') && request.method === 'POST') {
    if (!app.auth) throw new Failure('PASSKEY_AUTH_UNAVAILABLE', 503);
    await app.auth.rate('global');
    await app.auth.rate('ip:' + (request.headers.get('x-real-ip') ?? 'unknown').slice(0, 64));
    const data = await body(request, 16384);
    const required = (name: string) => z.string().max(4096).parse(data[name]);
    const loginResponse = async (session: { ownerId: string; token: string; csrf: string }) => {
      await app.catalogs.ensureBuiltIn(session.ownerId);
      const result = response({
        authenticated: true,
        csrf: session.csrf,
      });
      result.cookies.set('__Host-isign-session', session.token, {
        secure: true,
        httpOnly: true,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 86400,
      });
      result.cookies.set('isign-csrf', session.csrf, {
        secure: true,
        httpOnly: false,
        sameSite: 'strict',
        path: '/',
        maxAge: 7 * 86400,
      });
      return result;
    };
    if (target === 'auth/passkey/register-options')
      return response(await app.auth.registrationOptions(required('invite')));
    if (target === 'auth/passkey/register')
      return loginResponse(
        await app.auth.register(
          required('requestId'),
          z
            .object({ id: z.string().max(1024) })
            .passthrough()
            .parse(data.response) as unknown as RegistrationResponseJSON,
          raw,
        ),
      );
    if (target === 'auth/passkey/login-options')
      return response(await app.auth.authenticationOptions());
    if (target === 'auth/passkey/login')
      return loginResponse(
        await app.auth.authenticate(
          required('requestId'),
          z
            .object({ id: z.string().max(1024) })
            .passthrough()
            .parse(data.response) as unknown as AuthenticationResponseJSON,
          raw,
        ),
      );
    const authenticated = await app.sessions.authorizeWrite(
      raw,
      csrf,
      request.headers.get('origin') ?? '',
      origin,
    );
    if (target === 'auth/passkey/fresh-options')
      return response(await app.auth.authenticationOptions(authenticated.ownerId, raw));
    if (target === 'auth/passkey/fresh')
      return loginResponse(
        await app.auth.authenticate(
          required('requestId'),
          z
            .object({ id: z.string().max(1024) })
            .passthrough()
            .parse(data.response) as unknown as AuthenticationResponseJSON,
          raw,
        ),
      );
    if (target === 'auth/passkey/add-options') {
      await app.sessions.fresh(raw, csrf, request.headers.get('origin') ?? '', origin);
      return response(await app.auth.addOptions(authenticated.ownerId, raw));
    }
    throw new Failure('NOT_FOUND', 404);
  }
  return null;
}
