import { beforeEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
const { runtime } = vi.hoisted(() => ({ runtime: vi.fn() }));
vi.mock('../server/runtime', () => ({
  origin: 'https://isign.example.test',
  runtime,
}));
import { handle } from '../server/http/router';
const principal = { ownerId: 'u', sessionId: 'native-session' };
const nativeSessions = {
  start: vi.fn(),
  exchange: vi.fn(),
  refresh: vi.fn(),
  authorize: vi.fn(),
  logout: vi.fn(),
  complete: vi.fn(),
};
const service = { session: vi.fn(), authorizeWrite: vi.fn() };
beforeEach(() => {
  vi.resetAllMocks();
  runtime.mockResolvedValue({ nativeSessions, sessions: service });
  nativeSessions.authorize.mockResolvedValue(principal);
  nativeSessions.start.mockResolvedValue({ transactionId: 't' });
  nativeSessions.exchange.mockResolvedValue({ accessToken: 'a' });
  service.authorizeWrite.mockResolvedValue(principal);
});
function request(
  path: string,
  method = 'POST',
  headers: Record<string, string> = {},
  body: unknown = {},
) {
  return new NextRequest('https://isign.example.test/api/' + path, {
    method,
    headers: { host: 'isign.example.test', 'content-type': 'application/json', ...headers },
    ...(method === 'GET' ? {} : { body: JSON.stringify(body) }),
  });
}
it('exchanges native codes without Origin/cookie and never issues web cookies', async () => {
  const input = {
    transactionId: 't',
    code: 'c',
    codeVerifier: 'v'.repeat(43),
    redirectUri: 'isign-feather://auth/callback',
  };
  const res = await handle(request('native/v1/auth/exchange', 'POST', {}, input));
  expect(res.status).toBe(200);
  expect(nativeSessions.exchange).toHaveBeenCalledWith(input);
  expect(service.authorizeWrite).not.toHaveBeenCalled();
  expect(res.headers.get('set-cookie')).toBeNull();
});
it('rejects cookie-only native session requests', async () => {
  const res = await handle(
    request('native/v1/session', 'GET', { cookie: '__Host-isign-session=web' }),
  );
  expect(res.status).toBe(401);
  expect(service.session).not.toHaveBeenCalled();
  expect(nativeSessions.authorize).not.toHaveBeenCalled();
});
it('binds step-up to Bearer principal ignoring supplied sessionId', async () => {
  const input = {
    state: 's'.repeat(43),
    codeChallenge: 'c'.repeat(43),
    redirectUri: 'isign-feather://auth/callback',
    sessionId: 'attacker',
  };
  expect(
    (
      await handle(
        request('native/v1/auth/step-up', 'POST', { authorization: 'Bearer token' }, input),
      )
    ).status,
  ).toBe(200);
  expect(nativeSessions.authorize).toHaveBeenCalledWith('token');
  expect(nativeSessions.start).toHaveBeenCalledWith({ ...input, sessionId: 'native-session' });
});
it('ignores sessionId on public start', async () => {
  expect(
    (
      await handle(
        request(
          'native/v1/auth/start',
          'POST',
          {},
          {
            state: 's'.repeat(43),
            codeChallenge: 'c'.repeat(43),
            redirectUri: 'isign-feather://auth/callback',
            sessionId: 'attacker',
          },
        ),
      )
    ).status,
  ).toBe(200);
  expect(nativeSessions.start.mock.calls[0][0]).not.toHaveProperty('sessionId');
});
it('keeps Origin and cookie/CSRF checks on browser completion', async () => {
  expect(
    (
      await handle(
        request(
          'auth/native/complete',
          'POST',
          { authorization: 'Bearer native' },
          { transactionId: 't' },
        ),
      )
    ).status,
  ).toBe(403);
  nativeSessions.complete.mockResolvedValue({
    callbackUrl: 'isign-feather://auth/callback?code=c',
  });
  expect(
    (
      await handle(
        request(
          'auth/native/complete',
          'POST',
          {
            origin: 'https://isign.example.test',
            cookie: '__Host-isign-session=web',
            'x-isign-csrf': 'csrf',
          },
          { transactionId: 't' },
        ),
      )
    ).status,
  ).toBe(200);
  expect(service.authorizeWrite).toHaveBeenCalledWith(
    'web',
    'csrf',
    'https://isign.example.test',
    'https://isign.example.test',
  );
  expect(nativeSessions.complete).toHaveBeenCalledWith('t', 'web');
});
it('does not accept native Bearer as web session cookie', async () => {
  service.session.mockRejectedValue(new Error('missing cookie'));
  expect(
    (await handle(request('session', 'GET', { authorization: 'Bearer native' }))).status,
  ).not.toBe(200);
  expect(service.session).toHaveBeenCalledWith('');
  expect(nativeSessions.authorize).not.toHaveBeenCalled();
});
