import { beforeEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { Failure } from '../packages/core/src/shared/index';
const state = vi.hoisted(() => ({ readiness: vi.fn(), initialize: vi.fn() }));
vi.mock('../server/runtime', () => ({
  origin: 'https://synthetic.invalid',
  runtime: async () => {
    await state.initialize();
    return { readiness: state.readiness };
  },
}));
import { handle } from '../server/http/router';
beforeEach(() => {
  state.readiness.mockReset().mockResolvedValue(undefined);
  state.initialize.mockReset().mockResolvedValue(undefined);
});
function request(host = 'synthetic.invalid') {
  return new NextRequest('https://synthetic.invalid/api/health', { headers: { host } });
}
it('checks initialized runtime and broker without a user session', async () => {
  const response = await handle(request());
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ ready: true });
  expect(state.readiness).toHaveBeenCalledOnce();
  expect(response.headers.get('cache-control')).toContain('no-store');
});
it.each(['DATABASE_UNINITIALIZED', 'RUNNER_CONTROL_UNAVAILABLE'])(
  'fails readiness for %s',
  async (code) => {
    if (code === 'DATABASE_UNINITIALIZED')
      state.initialize.mockRejectedValue(new Failure(code, 503));
    else state.readiness.mockRejectedValue(new Failure(code, 503));
    const response = await handle(request());
    expect(response.status).toBe(503);
  },
);
it('rejects a noncanonical host before runtime initialization', async () => {
  expect((await handle(request('localhost'))).status).toBe(403);
  expect(state.initialize).not.toHaveBeenCalled();
});
