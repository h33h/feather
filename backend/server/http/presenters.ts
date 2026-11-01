import type { z } from 'zod';
import {
  librarySchema,
  appleSchema,
  devicesSchema,
  sourcesSchema,
  historySchema,
  sessionSchema,
  releasesSchema,
} from '../../packages/contracts/src/index';

/** Output failures are internal errors; request Zod validation remains HTTP 400. */
export class PresentationError extends Error {
  constructor(cause: unknown) {
    super('Server response failed contract validation', { cause });
    this.name = 'PresentationError';
  }
}
function present<S extends z.ZodType>(schema: S, value: unknown): z.output<S> {
  const result = schema.safeParse(value);
  if (!result.success) throw new PresentationError(result.error);
  return result.data;
}
export const presentLibrary = (value: unknown) => present(librarySchema, value);
export const presentApple = (value: unknown) => present(appleSchema, value);
export const presentDevices = (value: unknown) => present(devicesSchema, value);
export const presentSources = (value: unknown) => present(sourcesSchema, value);
export const presentHistory = (value: unknown) => present(historySchema, value);
export const presentSession = (value: unknown) => present(sessionSchema, value);
export const presentReleases = (value: unknown) => present(releasesSchema, value);
