import { z } from 'zod';
import { Failure, hash } from '../shared/index';
import { validateUrl } from './safe-fetch';
const text = z.string().min(1).max(500);
const app = z.object({
  appName: text,
  appVersion: z.string().max(500),
  appPackage: z.string().max(2048).optional(),
  appImage: z.string().max(2048).optional(),
  appDescription: z.string().max(20000).optional(),
  appBundleIdentifier: z.string().max(200).optional(),
  appBuild: z.string().max(100).optional(),
  appSHA256: z
    .string()
    .regex(/^[a-fA-F0-9]{64}$/)
    .optional(),
});
const schema = z.object({ appRepositories: z.array(app).max(20000) });
export type Release = {
  id: string;
  upstreamId: string;
  name: string;
  version: string | null;
  displayVersion: string;
  build: string | null;
  bundleId: string | null;
  digest: string | null;
  url: string;
  description: string;
  iconUrl?: string;
  feather?: { appIndex: number; versionIndices: number[]; topLevel: boolean };
};
export function normalizeGBox(input: unknown): Release[] {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new Failure('UNSUPPORTED_GBOX_SCHEMA');
  const seen = new Set<string>();
  return parsed.data.appRepositories.map((a) => {
    const url = a.appPackage ? validateUrl(a.appPackage).href : '';
    const upstreamId = a.appBundleIdentifier ?? hash(a.appName);
    const version =
      /^\s*([0-9]+(?:\.[0-9A-Za-z-]+)*)(?:\s*\||\s*$)/.exec(a.appVersion)?.[1] ?? null;
    const releaseId = hash(JSON.stringify([upstreamId, a.appVersion, a.appBuild ?? null, url]));
    if (seen.has(releaseId)) throw new Failure('DUPLICATE_RELEASE');
    seen.add(releaseId);
    return {
      id: releaseId,
      upstreamId,
      name: a.appName,
      version,
      displayVersion: a.appVersion,
      build: a.appBuild ?? null,
      bundleId: a.appBundleIdentifier ?? null,
      digest: a.appSHA256?.toLowerCase() ?? null,
      url,
      description: a.appDescription ?? '',
      iconUrl: a.appImage
        ? (() => {
            try {
              return validateUrl(a.appImage).href;
            } catch {
              return undefined;
            }
          })()
        : undefined,
    };
  });
}
