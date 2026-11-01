import type { z } from 'zod';
import type { Api } from './contracts';
import { parseResponse } from './response';

/** Validate the actual response before it enters browser state. */
export async function query<S extends z.ZodType>(
  api: Api,
  path: string,
  schema: S,
): Promise<z.output<S>> {
  return parseResponse(schema, await api(path));
}
