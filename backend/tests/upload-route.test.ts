import { expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
const state = vi.hoisted(() => ({ runtime: vi.fn() }));
vi.mock('../server/runtime', () => ({
  origin: 'https://upload.invalid',
  runtime: state.runtime,
}));
import * as route from '../../web/src/app/api/[...path]/route';
it('retires arbitrary browser source uploads before session lookup or byte consumption', async () => {
  for (const [method, path] of [
    ['POST', 'uploads'],
    ['PUT', 'uploads/source'],
  ] as const) {
    const response = await route[method](
      new NextRequest('https://upload.invalid/api/' + path, {
        method,
        headers: {
          host: 'upload.invalid',
          origin: 'https://upload.invalid',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          name: 'Arbitrary.ipa',
          key: 'key',
          url: 'https://evil.test/app.ipa',
        }),
      }),
    );
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({ code: 'NOT_FOUND' });
  }
  expect(state.runtime).not.toHaveBeenCalled();
});
