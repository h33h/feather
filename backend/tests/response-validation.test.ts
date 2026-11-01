import { expect, it } from 'vitest';
import { z } from 'zod';
import { inviteSchema } from '../packages/contracts/src/index';
import { parseResponse, readResponse } from '../../web/src/shared/api/response';
import { query } from '../../web/src/shared/api/query';
const displayMessage = 'Не удалось загрузить данные. Повторите попытку.';
it('gives admin invite actions safe text with the original schema error as cause', () => {
  let failure: unknown;
  try {
    parseResponse(inviteSchema, { token: 123 });
  } catch (error) {
    failure = error;
  }
  expect(failure).toMatchObject({ message: displayMessage, cause: expect.any(z.ZodError) });
  expect(String(failure)).not.toMatch(/token|invalid_type|expected/);
});
it('gives malformed success envelopes safe text before an action sees the error', async () => {
  const failure = await readResponse(
    { json: async () => ({ csrf: 123 }) },
    z.object({ csrf: z.string() }),
  ).catch((error: unknown) => error);
  expect(failure).toMatchObject({ message: displayMessage, cause: expect.any(z.ZodError) });
  expect(String(failure)).not.toMatch(/csrf|invalid_type|expected/);
});
it('gives malformed JSON safe text and keeps the decoding failure as cause', async () => {
  const cause = new SyntaxError('Unexpected private response body');
  const failure = await readResponse(
    {
      json: async () => {
        throw cause;
      },
    },
    inviteSchema,
  ).catch((error: unknown) => error);
  expect(failure).toMatchObject({ message: displayMessage, cause });
  expect(String(failure)).not.toContain('private');
});
it('leaves authenticated API errors intact so freshness and domain messages still work', async () => {
  const failure = Object.assign(new Error('Подтвердите вход.'), { code: 'FRESH_AUTH_REQUIRED' });
  await expect(
    query(
      async () => {
        throw failure;
      },
      'session',
      inviteSchema,
    ),
  ).rejects.toBe(failure);
});
