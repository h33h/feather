import { expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { Failure } from '../packages/core/src/shared/index';
const state = vi.hoisted(() => ({ app: null as unknown }));
vi.mock('../server/runtime', () => ({
  origin: 'https://synthetic.invalid',
  runtime: async () => state.app,
}));
import { handle } from '../server/http/router';

function fixture() {
  const reveal = vi.fn(async (_owner: string, id: string) => {
    if (id === 'foreign') throw new Failure('DEVICE_NOT_FOUND', 404);
    return { id, udid: '00008140-001234567890ABCD' };
  });
  state.app = {
    collections: { reveal },
    sessions: {
      session: async (raw: string) => {
        if (raw !== 'authenticated') throw new Failure('UNAUTHENTICATED', 401);
        return { ownerId: 'owner' };
      },
    },
  };
  return reveal;
}
function request(path = 'devices/collected/identity/udid', authenticated = true, method = 'GET') {
  return new NextRequest('https://synthetic.invalid/api/' + path, {
    method,
    headers: {
      host: 'synthetic.invalid',
      ...(authenticated ? { cookie: '__Host-isign-session=authenticated' } : {}),
    },
  });
}
it('routes the browser UDID request through authenticated owner lookup and never caches it', async () => {
  const reveal = fixture();
  const response = await handle(request());
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ id: 'identity', udid: '00008140-001234567890ABCD' });
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(reveal).toHaveBeenCalledExactlyOnceWith('owner', 'identity');
});
it('requires a live session before revealing a UDID', async () => {
  const reveal = fixture();
  const response = await handle(request(undefined, false));
  expect(response.status).toBe(401);
  expect(reveal).not.toHaveBeenCalled();
});
it('preserves owner lookup denials without revealing a foreign UDID', async () => {
  const reveal = fixture();
  const response = await handle(request('devices/collected/foreign/udid'));
  expect(response.status).toBe(404);
  expect(await response.json()).toMatchObject({ code: 'DEVICE_NOT_FOUND' });
  expect(reveal).toHaveBeenCalledExactlyOnceWith('owner', 'foreign');
});
it('allows only the exact read endpoint', async () => {
  const reveal = fixture();
  for (const input of [
    request('devices/collected/identity/udid/extra'),
    request(undefined, true, 'POST'),
  ])
    expect((await handle(input)).status).toBe(404);
  expect(reveal).not.toHaveBeenCalled();
});
