import { Failure, LIMITS, id } from '../shared/index';
import type { Database } from '../shared/database';
import type { StoragePort } from '../library/storage-contract';
import type { JobsActions } from '../signing/jobs-actions';
import { CatalogRegistry } from './registry';
import { fetchSafeStream, type Options } from './safe-fetch';
type Downloader = (
  url: string,
  options: Options,
) => Promise<Pick<Awaited<ReturnType<typeof fetchSafeStream>>, 'body' | 'finalOrigin'>>;
export class Importer {
  constructor(
    private db: Database,
    private catalogs: CatalogRegistry,
    private storage: StoragePort,
    private jobs: JobsActions,
    private download: Downloader = fetchSafeStream,
  ) {}
  async run(
    owner: string,
    sourceId: string,
    releaseId: string,
    snapshot: string,
    signal?: AbortSignal,
    input?: { key: string; deviceId?: string },
  ) {
    const selection = await this.catalogs.selection(owner, sourceId, releaseId, snapshot);
    const provenance = {
      sourceId,
      sourceName: selection.sourceName,
      sourceKind: selection.sourceKind,
      releaseId,
      snapshot,
      selectedVersion: selection.release.version,
      selectedDisplayVersion: selection.release.displayVersion,
      selectedBuild: selection.release.build,
      declaredBundleId: selection.release.bundleId,
      upstreamDigest: selection.release.digest,
    };
    const name = 'catalog-' + releaseId.slice(0, 12) + '.ipa';
    const operation = await this.jobs.beginSubmission(owner, {
      name,
      source: 'catalog',
      key: input?.key ?? 'import_' + id(),
      deviceId: input?.deviceId,
      provenance,
    });
    const current = (
      await this.db.query<{ state: string }>('SELECT state FROM jobs WHERE id=$1 AND owner_id=$2', [
        operation.jobId,
        owner,
      ])
    ).rows[0];
    if (current?.state !== 'receiving') return operation;
    try {
      const remote = await this.download(selection.release.url, {
        hosts: selection.hosts,
        maxBytes: LIMITS.upload,
        timeoutMs: 120000,
        signal,
      });
      await this.storage.upload(owner, name, remote.body, {
        ...operation,
        signal,
        expectedDigest: selection.release.digest ?? undefined,
        provenance: {
          ...provenance,
          receivedAt: this.jobs.queue.now,
          artifactOrigin: remote.finalOrigin,
        },
      });
      await this.catalogs.selection(owner, sourceId, releaseId, snapshot);
      await this.jobs.completeSource(owner, operation.jobId);
      return operation;
    } catch (error) {
      const code = error instanceof Failure ? error.code : 'IMPORT_INTERRUPTED';
      await this.jobs.queue.failReceiving(owner, operation.jobId, code);
      throw error instanceof Failure ? error : new Failure(code, 502);
    }
  }
  async select(owner: string, sourceId: string, releaseId: string, snapshot: string) {
    await this.catalogs.selection(owner, sourceId, releaseId, snapshot);
  }
}
