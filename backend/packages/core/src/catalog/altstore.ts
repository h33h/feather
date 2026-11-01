import { featherRepositorySchema, type FeatherRepository } from '../../../contracts/src';
import { Failure, hash } from '../shared/index';
import { normalizeGBox, type Release } from './gbox';
import { validateUrl } from './safe-fetch';

/** The source model currently has no scoped credential storage. Refuse private
 * feeds rather than embedding their auth in native media/package requests. */
function rejectCredentials(value: unknown, depth = 0): void {
  if (depth > 30) throw new Failure('SOURCE_FEED_TOO_COMPLEX');
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (
      /^(headers|downloadHeaders|authorization|authentication|credentials|userInfo|accessToken|token|cookie)$/i.test(
        key,
      ) &&
      child != null &&
      child !== '' &&
      (typeof child !== 'object' || Object.keys(child).length)
    )
      throw new Failure('SOURCE_AUTH_UNSUPPORTED', 409);
    rejectCredentials(child, depth + 1);
  }
}
function validateMetadataUrls(value: unknown): void {
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (
      typeof child === 'string' &&
      /^(website|patreonURL|iconURL|headerURL|downloadURL|imageURL|url)$/i.test(key)
    ) {
      if (child !== '') validateUrl(child);
    } else if (key === 'screenshotURLs' && Array.isArray(child)) {
      for (const url of child) validateUrl(url);
    } else if (key === 'screenshots') {
      const screenshots = Array.isArray(child) ? child : Object.values(child as object).flat();
      for (const screenshot of screenshots) {
        if (typeof screenshot === 'string') validateUrl(screenshot);
        else validateMetadataUrls(screenshot);
      }
    } else validateMetadataUrls(child);
  }
}
// Swift decodeIfPresent treats null optional object properties as absent.
// Keep array entries intact; required properties remain required by the schema.
function omitOptionalNulls(value: unknown, depth = 0): unknown {
  if (depth > 30) throw new Failure('SOURCE_FEED_TOO_COMPLEX');
  if (Array.isArray(value)) return value.map((child) => omitOptionalNulls(child, depth + 1));
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, child]) => child !== null)
      .map(([key, child]) => [key, omitOptionalNulls(child, depth + 1)]),
  );
}
export function normalizeCatalog(input: unknown): {
  releases: Release[];
  repository?: FeatherRepository;
} {
  let encoded: string;
  try {
    encoded = JSON.stringify(input);
  } catch {
    throw new Failure('UNSUPPORTED_SOURCE_SCHEMA');
  }
  if (!encoded || Buffer.byteLength(encoded) > 8 * 1024 ** 2)
    throw new Failure('REMOTE_TOO_LARGE', 413);
  const compatibleInput = omitOptionalNulls(input);
  rejectCredentials(compatibleInput);
  if (!input || typeof input !== 'object' || !('apps' in input)) return normalizeGBoxCatalog(input);
  const parsed = featherRepositorySchema.safeParse(compatibleInput);
  if (!parsed.success) throw new Failure('UNSUPPORTED_ALTSTORE_SCHEMA');
  const repository = parsed.data;
  validateMetadataUrls(repository);
  const releases: Release[] = [];
  const seen = new Set<string>();
  for (const [appIndex, app] of repository.apps.entries()) {
    if (app.marketplaceID?.trim()) throw new Failure('SOURCE_MARKETPLACE_UNSUPPORTED');
    const upstreamId =
      app.bundleIdentifier ?? hash(JSON.stringify([app.name, app.iconURL, appIndex]));
    const appReleases: Release[] = [];
    const add = (
      version: string,
      build: string | undefined,
      url: string | undefined,
      versionIndices: number[],
      topLevel: boolean,
    ) => {
      const releaseId = hash(JSON.stringify([upstreamId, version, build ?? null, url ?? '']));
      if (seen.has(releaseId)) throw new Failure('DUPLICATE_RELEASE');
      seen.add(releaseId);
      const release: Release = {
        id: releaseId,
        upstreamId,
        name: app.name ?? 'Unknown',
        version: version || null,
        displayVersion: version,
        build: build ?? null,
        bundleId: app.bundleIdentifier ?? null,
        digest: null,
        url: url ? validateUrl(url).href : '',
        description: app.localizedDescription ?? app.description ?? app.subtitle ?? '',
        iconUrl: app.iconURL,
        feather: { appIndex, versionIndices, topLevel },
      };
      releases.push(release);
      appReleases.push(release);
    };
    for (const [index, version] of (app.versions ?? []).entries())
      add(version.version, version.buildVersion, version.downloadURL, [index], false);
    const top = appReleases.find((r) => r.url === app.downloadURL);
    if (top) top.feather!.topLevel = true;
    else if (app.downloadURL || !appReleases.length)
      add(app.version ?? '', undefined, app.downloadURL, [], true);
    else appReleases[0].feather!.topLevel = true;
    if (releases.length > 20000) throw new Failure('SOURCE_RELEASE_LIMIT');
  }
  return { releases, repository };
}

function normalizeGBoxCatalog(input: unknown): {
  releases: Release[];
  repository?: FeatherRepository;
} {
  const releases = normalizeGBox(input);
  if (!releases.length) return { releases };
  const raw = input as Record<string, unknown> & { appRepositories: Record<string, unknown>[] };
  const text = (value: unknown, max: number) =>
    typeof value === 'string' && value.length <= max ? value : undefined;
  const url = (value: unknown) => {
    if (typeof value !== 'string' || !value) return undefined;
    try {
      return validateUrl(value).href;
    } catch {
      return undefined;
    }
  };
  const date = (value: unknown) => {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (
      typeof value === 'string' &&
      value.length <= 100 &&
      /^\d{4}-\d{2}-\d{2}/.test(value) &&
      Number.isFinite(Date.parse(value))
    )
      return value;
    return undefined;
  };
  const repository: FeatherRepository = {
    name: text(raw.sourceName, 500),
    description: text(raw.sourceDescription, 20000),
    iconURL: url(raw.sourceImage),
    website: url(raw.sourceLinkUrl),
    apps: releases.map((release, appIndex) => {
      const app = raw.appRepositories[appIndex];
      const version = release.version ?? release.displayVersion;
      release.feather = { appIndex, versionIndices: version ? [0] : [], topLevel: true };
      return {
        bundleIdentifier: release.bundleId ?? release.upstreamId,
        name: release.name,
        version,
        localizedDescription: release.description,
        developerName: text(app.appAuthor, 500),
        iconURL: release.iconUrl,
        versionDate: date(app.appUpdateTime),
        downloadURL: release.url || undefined,
        versions: version
          ? [
              {
                version,
                buildVersion: release.build ?? undefined,
                date: date(app.appUpdateTime),
                downloadURL: release.url || undefined,
              },
            ]
          : undefined,
      };
    }),
  };
  return { releases, repository };
}
