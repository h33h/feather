import { expect, it } from 'vitest';
import type { Api, AuthSession } from '../../web/src/shared/api/contracts';
import { loadSession } from '../../web/src/shared/api/session-loader';
const session = {
  csrf: 'csrf',
  profile: { id: 'one', loginName: 'user', role: 'user' },
  capabilities: {},
};
function deferred() {
  let resolve!: (value: Awaited<ReturnType<Api>>) => void;
  const promise = new Promise<Awaited<ReturnType<Api>>>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
function fixture() {
  const generation = { current: 0 };
  const request = { current: null as Promise<AuthSession | null> | null };
  const accepted: AuthSession[] = [];
  const accept = (value: AuthSession) => {
    accepted.push(value);
  };
  return { generation, request, accepted, accept };
}
it('validates session data and never accepts malformed responses', async () => {
  const state = fixture();
  await expect(loadSession(async () => ({ csrf: 'csrf', profile: {} }), state)).rejects.toThrow();
  expect(state.accepted).toEqual([]);
  expect(state.request.current).toBeNull();
});
it('drops extra session and nested profile columns before accepting', async () => {
  const state = fixture();
  await loadSession(
    async () => ({
      ...session,
      session_hash: 'secret',
      profile: { ...session.profile, secret_ref: 'secret' },
    }),
    state,
  );
  expect(state.accepted).toEqual([session]);
});
it('does not restore a session from an in-flight response after logout', async () => {
  const state = fixture(),
    pending = deferred();
  const work = loadSession(() => pending.promise, state);
  state.generation.current++;
  state.request.current = null;
  pending.resolve(session);
  await expect(work).resolves.toBeNull();
  expect(state.accepted).toEqual([]);
});
it('deduplicates requests and only accepts the latest forced refresh', async () => {
  const state = fixture(),
    old = deferred(),
    fresh = deferred();
  const first = loadSession(() => old.promise, state);
  expect(loadSession(() => old.promise, state)).toBe(first);
  const next = loadSession(() => fresh.promise, state, true);
  old.resolve(session);
  await expect(first).resolves.toBeNull();
  expect(state.request.current).toBe(next);
  const updated = { ...session, profile: { ...session.profile, id: 'two' } };
  fresh.resolve(updated);
  await expect(next).resolves.toEqual(updated);
  expect(state.accepted).toEqual([updated]);
});
it('keeps malformed post-action session diagnostics out of the action error message', async () => {
  const { z } = await import('zod');
  const state = fixture();
  const failure = await loadSession(
    async () => ({ ...session, profile: { ...session.profile, role: 'root' } }),
    state,
    true,
  ).catch((error: unknown) => error);
  expect(failure).toMatchObject({
    message: 'Не удалось загрузить данные. Повторите попытку.',
    cause: expect.any(z.ZodError),
  });
  expect(String(failure)).not.toMatch(/invalid_value|profile|role|issues/);
  expect(state.accepted).toEqual([]);
});
