import { beforeEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { presentApple } from '../server/http/presenters';
const state = vi.hoisted(() => ({ app: null as unknown }));
vi.mock('../server/runtime', () => ({
  origin: 'https://contracts.invalid',
  runtime: async () => state.app,
}));
import { handle } from '../server/http/router';
beforeEach(() => {
  const session = { ownerId: 'o', role: 'admin', loginName: 'owner' };
  state.app = {
    sessions: {
      session: async () => session,
      authorizeWrite: async () => session,
      fresh: async () => {},
    },
    connectApple: async () => ({}),
    sharing: { list: async () => [] },
    queries: { apple: async () => ({ connection: 'malformed' }) },
  };
});
it('keeps output validation diagnostics in an internal error cause', () => {
  const failure = (() => {
    try {
      presentApple({});
    } catch (error) {
      return error;
    }
  })();
  expect(failure).toBeInstanceOf(Error);
  expect(failure).not.toBeInstanceOf(z.ZodError);
  expect(failure).toMatchObject({ cause: expect.any(z.ZodError) });
});
it('classifies malformed server output as HTTP 500 rather than invalid request', async () => {
  const response = await handle(
    new NextRequest('https://contracts.invalid/api/apple', {
      headers: { host: 'contracts.invalid' },
    }),
  );
  expect(response.status).toBe(500);
  expect(await response.json()).toMatchObject({ code: 'INTERNAL_ERROR' });
});
it('retains HTTP 400 for invalid client request fields', async () => {
  const response = await handle(
    new NextRequest('https://contracts.invalid/api/apple/connect', {
      method: 'POST',
      headers: {
        host: 'contracts.invalid',
        origin: 'https://contracts.invalid',
        'content-type': 'application/json',
      },
      body: JSON.stringify({ name: 123 }),
    }),
  );
  expect(response.status).toBe(400);
  expect(await response.json()).toMatchObject({ code: 'INVALID_REQUEST' });
});
