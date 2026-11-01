import { beforeEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
const { runtime } = vi.hoisted(() => ({ runtime: vi.fn() }));
vi.mock('../server/runtime', () => ({
  origin: 'https://isign.example.test',
  runtime,
}));
import { handle } from '../server/http/router';
const raw = 'a'.repeat(43);
const query = vi.fn(),
  command = vi.fn();
beforeEach(() => {
  vi.resetAllMocks();
  query.mockResolvedValue({ value: 'private' });
  command.mockResolvedValue({ ok: true });
  runtime.mockResolvedValue({ nativeSessions: {}, nativeApplication: { view: query, command } });
});
function request(
  path: string,
  method = 'GET',
  data: unknown = {},
  headers: Record<string, string> = {},
) {
  return new NextRequest('https://isign.example.test/api/native/v1/' + path, {
    method,
    headers: {
      host: 'isign.example.test',
      authorization: 'Bearer ' + raw,
      'content-type': 'application/json',
      ...headers,
    },
    ...(method === 'GET' ? {} : { body: JSON.stringify(data) }),
  });
}
it.each([
  ['apple', { kind: 'apple' }],
  ['devices', { kind: 'devices' }],
  ['sources', { kind: 'sources' }],
  ['sources/s1/feed', { kind: 'source.feed', id: 's1' }],
  ['devices/collected/d1/udid', { kind: 'device.udid', id: 'd1' }],
  ['signing/identity', { kind: 'signing.identity' }],
  ['signing/profiles/o1', { kind: 'signing.profiles', id: 'o1' }],
  ['admin/users', { kind: 'admin.users' }],
])('routes native GET %s with bearer-only private responses', async (path, expected) => {
  const res = await handle(request(path as string));
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({ value: 'private' });
  expect(query).toHaveBeenCalledWith(raw, expected);
  expect(res.headers.get('cache-control')).toBe('no-store');
  expect(res.headers.get('set-cookie')).toBeNull();
});
it.each([
  [
    'apple/connect',
    { filename: 'AuthKey_A.p8', issuerId: 'issuer', keyId: 'A', p8: 'key' },
    {
      kind: 'apple.connect',
      input: { filename: 'AuthKey_A.p8', issuerId: 'issuer', keyId: 'A', p8: 'key' },
    },
  ],
  ['apple/disconnect', {}, { kind: 'apple.disconnect' }],
  ['apple/bootstrap', {}, { kind: 'apple.bootstrap' }],
  [
    'apple/shares',
    { publicProfileId: 'profile_x' },
    { kind: 'apple.share', profileId: 'profile_x' },
  ],
  ['apple/shares/g1/revoke', {}, { kind: 'apple.revokeShare', id: 'g1' }],
  [
    'devices/d1/register',
    { slotConsent: true },
    { kind: 'device.register', id: 'd1', slotConsent: true },
  ],
  ['devices/d1/poll', {}, { kind: 'device.poll', id: 'd1' }],
  ['devices/d1/os', { version: '27.0' }, { kind: 'device.os', id: 'd1', version: '27.0' }],
  ['devices/d1/rename', { name: 'Phone' }, { kind: 'device.rename', id: 'd1', name: 'Phone' }],
  ['devices/d1/select', {}, { kind: 'device.select', id: 'd1' }],
  ['devices/d1/remove', {}, { kind: 'device.remove', id: 'd1' }],
  ['devices/collected/d1/remove', {}, { kind: 'device.removeCollected', id: 'd1' }],
  [
    'sources',
    { name: 'Apps', url: 'https://apps.example/feed', trustPublisher: true },
    { kind: 'source.add', name: 'Apps', url: 'https://apps.example/feed', trustPublisher: true },
  ],
  ['sources/s1/refresh', {}, { kind: 'source.refresh', id: 's1' }],
  ['sources/s1/disable', {}, { kind: 'source.disable', id: 's1' }],
  ['sources/s1/remove', {}, { kind: 'source.remove', id: 's1' }],
  ['sources/s1/rename', { name: 'Apps' }, { kind: 'source.rename', id: 's1', name: 'Apps' }],
  [
    'sources/s1/download',
    { releaseId: 'r1', snapshot: 'snap' },
    { kind: 'source.download', sourceId: 's1', releaseId: 'r1', snapshot: 'snap' },
  ],
  ['signing/identity/ensure', { retry: true }, { kind: 'signing.ensure', retry: true }],
  ['signing/identity/revoke', {}, { kind: 'signing.revoke' }],
  ['signing/bundle', {}, { kind: 'signing.bundle' }],
  [
    'signing/profiles/ensure',
    { deviceIds: ['d1'], bundles: [{ bundleId: 'com.example.app', entitlements: {} }] },
    {
      kind: 'signing.profiles',
      request: { deviceIds: ['d1'], bundles: [{ bundleId: 'com.example.app', entitlements: {} }] },
    },
  ],
  ['admin/invites', { name: 'guest' }, { kind: 'admin.invite', name: 'guest' }],
  ['admin/users/u1/reinvite', {}, { kind: 'admin.reinvite', id: 'u1' }],
  ['admin/users/u1/block', {}, { kind: 'admin.block', id: 'u1' }],
  ['admin/users/u1/unblock', {}, { kind: 'admin.unblock', id: 'u1' }],
  ['account/delete', {}, { kind: 'account.delete' }],
])('maps native POST %s to its explicit owner command', async (path, data, expected) => {
  const res = await handle(request(path as string, 'POST', data));
  expect(res.status).toBe(200);
  expect(command).toHaveBeenCalledWith(raw, expected);
});
it('maps admin delete and formats a native device collection profile link', async () => {
  expect((await handle(request('admin/users/u1', 'DELETE'))).status).toBe(200);
  expect(command).toHaveBeenLastCalledWith(raw, { kind: 'admin.remove', id: 'u1' });
  command.mockResolvedValue({ challenge: 'c'.repeat(43), expiresAt: 600000 });
  const res = await handle(request('devices/challenge', 'POST'));
  expect(await res.json()).toMatchObject({
    profileUrl: 'https://isign.example.test/device-profile/' + 'c'.repeat(43),
    expiresAt: 600000,
  });
});
it('rejects cookie-only resource calls, malformed data, and disabled native resources', async () => {
  expect(
    (
      await handle(
        request('sources', 'GET', {}, { authorization: '', cookie: '__Host-isign-session=web' }),
      )
    ).status,
  ).toBe(401);
  expect(
    (await handle(request('devices/d1/register', 'POST', { slotConsent: 'yes' }))).status,
  ).toBe(400);
  expect(command).not.toHaveBeenCalled();
  runtime.mockResolvedValue({});
  expect((await handle(request('sources'))).status).toBe(503);
});
