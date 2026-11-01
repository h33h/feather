import type { z } from 'zod';

/** This message may be displayed by session/action/admin consumers. */
class ResponseDataError extends Error {
  constructor(cause: unknown) {
    super('Не удалось загрузить данные. Повторите попытку.', { cause });
    this.name = 'ResponseDataError';
  }
}
export function parseResponse<S extends z.ZodType>(schema: S, value: unknown): z.output<S> {
  const result = schema.safeParse(value);
  if (!result.success) throw new ResponseDataError(result.error);
  return result.data;
}
export async function readResponse<S extends z.ZodType>(
  response: Pick<Response, 'json'>,
  schema: S,
): Promise<z.output<S>> {
  let value: unknown;
  try {
    value = await response.json();
  } catch (cause) {
    throw new ResponseDataError(cause);
  }
  return parseResponse(schema, value);
}
