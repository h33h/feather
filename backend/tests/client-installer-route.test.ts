import { beforeEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { Failure } from '../packages/core/src/shared';
const state = vi.hoisted(() => ({ app: null as unknown, runtime: vi.fn() }));
vi.mock('../server/runtime', () => ({
  origin: 'https://installer.invalid',
  runtime: state.runtime,
}));
import { handle } from '../server/http/router';
const session = vi.fn(),
  write = vi.fn(),
  fresh = vi.fn(),
  begin = vi.fn(),
  view = vi.fn(),
  ticket = vi.fn();
beforeEach(() => {
  vi.resetAllMocks();
  session.mockResolvedValue({ ownerId: 'owner' });
  write.mockResolvedValue({ ownerId: 'owner' });
  fresh.mockResolvedValue({ ownerId: 'owner' });
  begin.mockResolvedValue({ operationId: 'operation', jobId: 'job', state: 'queued' });
  view.mockResolvedValue({ operationId: 'operation', jobId: 'job', state: 'ready' });
  ticket.mockResolvedValue({ ticket: 'a'.repeat(43), expiresAt: 10000 });
  state.app = {
    service: { session, authorizeWrite: write, fresh },
    clientInstaller: {
      release: async () => ({
        name: 'iSign Client',
        available: false,
        reason: 'CLIENT_RELEASE_NOT_CONFIGURED',
      }),
      begin,
      view,
      ticket,
    },
  };
  state.runtime.mockImplementation(async () => state.app);
});
function request(target: string, method = 'GET', data: unknown = {}, headers = {}) {
  return new NextRequest('https://installer.invalid/api/' + target, {
    method,
    headers: {
      host: 'installer.invalid',
      origin: 'https://installer.invalid',
      'content-type': 'application/json',
      'x-isign-csrf': 'csrf',
      ...headers,
    },
    ...(method === 'GET' ? {} : { body: JSON.stringify(data) }),
  });
}
it('provides safe release status without requiring a session', async () => {
  const res = await handle(request('client/release'));
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({
    name: 'iSign Client',
    available: false,
    reason: 'CLIENT_RELEASE_NOT_CONFIGURED',
  });
  expect(session).not.toHaveBeenCalled();
});
it.each([
  'uploads',
  'uploads/source',
  'library',
  'history',
  'artifacts/a/ticket',
  'catalog',
  'sources',
  'jobs/ensure',
  'admin/users',
  'apple/shares',
  'devices/d/rename',
  'account/delete',
])('denies retired browser API %s before session or runtime access', async (target) => {
  expect((await handle(request(target, 'POST'))).status).toBe(404);
  expect(state.runtime).not.toHaveBeenCalled();
});
it.each([
  { deviceId: 'device', key: 'one', uploadId: 'evil' },
  { deviceId: 'device', key: 'one', url: 'https://evil.test/x.ipa' },
  { deviceId: 'device', key: 'one', path: '/private/evil.ipa' },
  { deviceId: 'device', key: 'bad key' },
])('rejects arbitrary source and malformed install fields', async (data) => {
  const res = await handle(request('client/install', 'POST', data));
  expect(res.status).toBe(400);
  expect(begin).not.toHaveBeenCalled();
});
it('starts only the fixed client after session CSRF and fresh authentication', async () => {
  const res = await handle(request('client/install', 'POST', { deviceId: 'device', key: 'one' }));
  expect(res.status).toBe(200);
  expect(begin).toHaveBeenCalledWith('owner', { deviceId: 'device', key: 'one' });
  expect(write).toHaveBeenCalled();
  expect(fresh).toHaveBeenCalled();
  fresh.mockRejectedValueOnce(new Failure('FRESH_AUTH_REQUIRED', 403));
  expect(
    (await handle(request('client/install', 'POST', { deviceId: 'device', key: 'two' }))).status,
  ).toBe(403);
  expect(begin).toHaveBeenCalledTimes(1);
});
it('scopes status and ticket to the operation and refuses nominated artifacts', async () => {
  expect((await handle(request('client/install/operation'))).status).toBe(200);
  expect(view).toHaveBeenCalledWith('owner', 'operation');
  expect(
    (await handle(request('client/install/operation/ticket', 'POST', { artifactId: 'evil' })))
      .status,
  ).toBe(400);
  expect(ticket).not.toHaveBeenCalled();
  const res = await handle(request('client/install/operation/ticket', 'POST'));
  expect(res.status).toBe(200);
  expect(await res.json()).toMatchObject({
    installUrl: expect.stringMatching(/^itms-services:/),
    handoffUrl: 'https://installer.invalid/handoff/' + 'a'.repeat(43),
    qrSvg: expect.stringContaining('<svg'),
    expiresAt: 10000,
  });
  expect(ticket).toHaveBeenCalledWith('owner', 'operation');
});
it('rejects foreign origins before installer writes', async () => {
  expect(
    (
      await handle(
        request(
          'client/install',
          'POST',
          { deviceId: 'd', key: 'one' },
          { origin: 'https://evil.test' },
        ),
      )
    ).status,
  ).toBe(403);
  expect(begin).not.toHaveBeenCalled();
});
it('enforces persisted cookie sessions, CSRF and ten-minute freshness on the installer route', async () => {
  const { createDatabase } = await import('./helpers/database');
  const { loginFixture } = await import('./helpers/login');
  const { SessionService } = await import('../packages/core/src/auth/sessions');
  const db = await createDatabase(),
    login = await loginFixture(db, 'route-owner', 1000);
  let now = 1000;
  const service = new SessionService(db, { now: () => now });
  state.app = { ...(state.app as object), service };
  const input = { deviceId: 'device', key: 'authenticated' };
  expect((await handle(request('client/install', 'POST', input))).status).toBe(401);
  const headers = { cookie: '__Host-isign-session=' + login.token, 'x-isign-csrf': login.csrf };
  expect(
    (
      await handle(
        request('client/install', 'POST', input, { ...headers, 'x-isign-csrf': 'wrong' }),
      )
    ).status,
  ).toBe(403);
  expect(begin).not.toHaveBeenCalled();
  expect((await handle(request('client/install', 'POST', input, headers))).status).toBe(200);
  expect(begin).toHaveBeenCalledWith(login.ownerId, input);
  now += 600000;
  const expired = await handle(request('client/install', 'POST', input, headers));
  expect(expired.status).toBe(403);
  expect(await expired.json()).toMatchObject({ code: 'FRESH_AUTH_REQUIRED' });
  expect(begin).toHaveBeenCalledTimes(1);
});
