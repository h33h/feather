import { handleClientInstaller } from './client-installer';
import { handleNativeAuth, handleNativeCompletion } from './native-auth';
import { handleNative } from './native';
import type { HttpApplication } from './application';
import { NextRequest } from 'next/server';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { runtime as getRuntime, origin } from '../runtime';
import { ProviderError } from '../../packages/core/src/shared/errors';
import { Failure } from '../../packages/core/src/shared/index';
import { handleRunner } from './runner';
import { handleCallback } from './callback';
import { handlePublicAuth } from './public-auth';
import { handleDevices } from './devices';
import { handleSession } from './session';
import { handleApple } from './apple';
import { handleAccount } from './account';
import { response } from './common';
/** Browser capabilities are limited to enrolling and installing the fixed client. */
function browserRoute(target: string, method: string) {
  if (method === 'GET')
    return (
      ['health', 'client/release', 'session', 'apple', 'devices'].includes(target) ||
      /^client\/install\/[^/]+$/.test(target) ||
      /^devices\/collected\/[^/]+\/udid$/.test(target)
    );
  if (method !== 'POST') return false;
  return (
    target.startsWith('auth/passkey/') ||
    [
      'auth/logout',
      'auth/native/complete',
      'apple/connect',
      'apple/bootstrap',
      'apple/disconnect',
      'devices/challenge',
      'devices/callback',
      'client/install',
    ].includes(target) ||
    /^devices\/[^/]+\/(register|poll|select|os)$/.test(target) ||
    /^client\/install\/[^/]+\/ticket$/.test(target)
  );
}
export async function handle(request: NextRequest) {
  const target = request.nextUrl.pathname.slice('/api/'.length);
  try {
    if (request.headers.get('host') !== new URL(origin).host)
      throw new Failure('INVALID_HOST', 403);
    if (
      !target.startsWith('native/v1/') &&
      !target.startsWith('runner/') &&
      !browserRoute(target, request.method)
    )
      throw new Failure('NOT_FOUND', 404);
    const app: HttpApplication = await getRuntime();
    if (target === 'client/release' && request.method === 'GET')
      return response(await app.clientInstaller.release());
    if (target === 'health' && request.method === 'GET') {
      await app.readiness();
      return response({ ready: true });
    }
    const runnerResult = await handleRunner({ request, target, app, raw: '', csrf: '' });
    if (runnerResult) return runnerResult;
    const nativeResult = await handleNativeAuth({ request, target, app, raw: '', csrf: '' });
    if (nativeResult) return nativeResult;
    const nativeResource = await handleNative({ request, target, app, raw: '', csrf: '' });
    if (nativeResource) return nativeResource;
    if (target.startsWith('native/v1/')) throw new Failure('NOT_FOUND', 404);
    const raw = request.cookies.get('__Host-isign-session')?.value ?? '';
    const csrf = request.headers.get('x-isign-csrf') ?? '';
    const callbackResult = await handleCallback({ request, target, app, raw, csrf });
    if (callbackResult) return callbackResult;
    if (request.method !== 'GET' && request.headers.get('origin') !== origin)
      throw new Failure('CSRF', 403);
    const completion = await handleNativeCompletion({ request, target, app, raw, csrf });
    if (completion) return completion;
    const publicResult = await handlePublicAuth({ request, target, app, raw, csrf });
    if (publicResult) return publicResult;
    const session =
      request.method === 'GET'
        ? await app.sessions.session(raw)
        : await app.sessions.authorizeWrite(raw, csrf, request.headers.get('origin') ?? '', origin);
    const owner = session.ownerId;
    const authenticatedContext = {
      request,
      target,
      app,
      raw,
      csrf,
      owner,
      session,
    };
    const handlers: Record<
      string,
      (
        context: typeof authenticatedContext,
      ) => Promise<import('next/server').NextResponse | undefined | null>
    > = {
      client: handleClientInstaller,
      devices: handleDevices,
      session: handleSession,
      apple: handleApple,
      auth: handleAccount,
    };
    const handler = handlers[target.split('/')[0]];
    if (handler) {
      const result = await handler(authenticatedContext);
      if (result) return result;
    }
    throw new Failure('NOT_FOUND', 404);
  } catch (error) {
    if (error instanceof z.ZodError)
      return response({ code: 'INVALID_REQUEST', requestId: randomUUID() }, 400);
    const failure =
      error instanceof Failure
        ? error
        : error instanceof ProviderError
          ? new Failure('PROVIDERS_UNAVAILABLE', 503)
          : new Failure('INTERNAL_ERROR', 500);
    return response({ code: failure.code, requestId: randomUUID() }, failure.status);
  }
}
