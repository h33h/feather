import {
  featherDownloadInputSchema,
  featherDownloadSchema,
  featherFeedSchema,
  featherSourcesSchema,
  type FeatherRepository,
} from '../../../contracts/src';
import type { Database } from '../shared/database';
import { Failure } from '../shared/index';
import type { Release } from './gbox';
import { CatalogRegistry } from './registry';
import { CURRENT_GBOX_URL } from './feed';
import { fetchSafeStream, validateUrl } from './safe-fetch';

type Source = {
  id: string;
  name: string;
  kind: string;
  revision: number;
  state: string;
  canonical_url: string | null;
  last_error: string | null;
  feed: { hosts: string[]; snapshot?: string; repository?: FeatherRepository } | null;
};
type StoredRelease = { id: string; snapshot: string; metadata: Release };
export type FeatherCatalogPorts = { now: () => number; fetch?: typeof fetchSafeStream };

/** A native projection over the authoritative source registry. No native access
 * token or source credential is ever part of a repository or descriptor. */
export class FeatherCatalog {
  constructor(
    private db: Database,
    private catalogs: CatalogRegistry,
    private ports: FeatherCatalogPorts,
  ) {}
  async list(ownerId: string) {
    const result = await this.db.query<Source>(
      "SELECT id,name,kind,revision,state,canonical_url FROM sources WHERE owner_id=$1 AND state<>'deleted' ORDER BY kind,id",
      [ownerId],
    );
    return featherSourcesSchema.parse({
      sources: result.rows.map((source) => ({
        id: source.id,
        name: source.name,
        revision: source.revision,
        state: source.state,
        canonicalUrl: source.canonical_url ?? (source.kind === 'iapps' ? CURRENT_GBOX_URL : null),
      })),
    });
  }
  async feed(ownerId: string, sourceId: string) {
    if (!sourceId || sourceId.length > 200) throw new Failure('NOT_FOUND', 404);
    return this.db.transaction(async (tx) => {
      const result = await tx.query<Source>(
        'SELECT * FROM sources WHERE id=$1 AND owner_id=$2 FOR SHARE',
        [sourceId, ownerId],
      );
      const source = result.rows[0];
      if (!source) throw new Failure('NOT_FOUND', 404);
      if (source.state !== 'ready') throw new Failure('SOURCE_DISABLED', 409);
      if (source.last_error === 'GBOX_EXPORT_CHANGED')
        throw new Failure('SOURCE_REVIEW_REQUIRED', 409);
      const rows = (
        await tx.query<StoredRelease>(
          'SELECT id,snapshot,metadata FROM releases WHERE source_id=$1 AND owner_id=$2 ORDER BY id',
          [sourceId, ownerId],
        )
      ).rows;
      const snapshot = source.feed?.snapshot ?? rows[0]?.snapshot;
      if (!snapshot || !rows.length) throw new Failure('SOURCE_METADATA_ONLY', 409);
      if (rows.some((row) => row.snapshot !== snapshot))
        throw new Failure('RELEASE_UNAVAILABLE', 409);
      const marker = (id: string) =>
        `isign-feather://download/${encodeURIComponent(sourceId)}/${encodeURIComponent(id)}?snapshot=${encodeURIComponent(snapshot)}`;
      let repository: FeatherRepository;
      if (source.feed?.repository) {
        repository = structuredClone(source.feed.repository);
        repository.name ??= source.name;
        repository.identifier ??= source.id;
        // Replace every raw package URL, including top-level and historical
        // entries. Media URLs remain public and receive no native headers.
        for (const app of repository.apps) {
          delete app.downloadURL;
          for (const version of app.versions ?? []) delete version.downloadURL;
        }
        for (const row of rows) {
          const mapping = row.metadata.feather;
          if (!mapping) throw new Failure('RELEASE_UNAVAILABLE', 409);
          const app = repository.apps[mapping.appIndex];
          if (!app) throw new Failure('RELEASE_UNAVAILABLE', 409);
          if (!row.metadata.url) continue;
          if (mapping.topLevel) app.downloadURL = marker(row.id);
          for (const index of mapping.versionIndices) {
            const version = app.versions?.[index];
            if (!version) throw new Failure('RELEASE_UNAVAILABLE', 409);
            version.downloadURL = marker(row.id);
          }
        }
      } else {
        // Existing pre-feature snapshots need no migration or refresh.
        repository = {
          identifier: source.id,
          name: source.name,
          apps: rows.map((row) => {
            const release = row.metadata;
            const version = release.version ?? release.displayVersion;
            return {
              bundleIdentifier: release.bundleId ?? release.upstreamId,
              name: release.name,
              version,
              localizedDescription: release.description,
              iconURL: release.iconUrl,
              ...(release.url ? { downloadURL: marker(row.id) } : {}),
              versions: version
                ? [
                    {
                      version,
                      ...(release.build ? { buildVersion: release.build } : {}),
                      ...(release.url ? { downloadURL: marker(row.id) } : {}),
                    },
                  ]
                : undefined,
            };
          }),
        };
      }
      return featherFeedSchema.parse({ sourceId, snapshot, repository });
    });
  }
  async download(ownerId: string, input: unknown) {
    const parsed = featherDownloadInputSchema.safeParse(input);
    if (!parsed.success) throw new Failure('INVALID_DOWNLOAD_REFERENCE');
    const { sourceId, releaseId, snapshot } = parsed.data;
    const selected = await this.catalogs.selection(ownerId, sourceId, releaseId, snapshot);
    const url = validateUrl(selected.release.url);
    if (!selected.hosts.includes(url.hostname)) throw new Failure('ARTIFACT_HOST_NOT_APPROVED');
    // Resolve redirects through the existing DNS-pinned exact-host policy.
    // No package bytes are consumed and no source or native auth is forwarded.
    const response = await (this.ports.fetch ?? fetchSafeStream)(url.href, {
      hosts: selected.hosts,
      timeoutMs: 10000,
      maxBytes: 1024 ** 3,
    });
    let closed = false;
    try {
      const target = validateUrl(response.finalUrl);
      if (!selected.hosts.includes(target.hostname))
        throw new Failure('ARTIFACT_HOST_NOT_APPROVED');
      await response.close();
      closed = true;
      // A concurrent refresh/removal must not turn an obsolete selection into a
      // newly authorized download after a slow remote preflight.
      const current = await this.catalogs.selection(ownerId, sourceId, releaseId, snapshot);
      if (!current.hosts.includes(target.hostname)) throw new Failure('ARTIFACT_HOST_NOT_APPROVED');
      return featherDownloadSchema.parse({
        url: target.href,
        headers: {},
        expiresAt: this.ports.now() + 60000,
      });
    } finally {
      if (!closed) await response.close();
    }
  }
}
