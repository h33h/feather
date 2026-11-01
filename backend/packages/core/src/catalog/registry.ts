import type { Database } from '../shared/database';
import { Failure, hash, id } from '../shared/index';
import type { Release } from './gbox';
import type { FeatherRepository } from '../../../contracts/src';
import { normalizeCatalog } from './altstore';
import { validateUrl, fetchSafe } from './safe-fetch';
import { CURRENT_GBOX_URL, CURRENT_PACKAGE_HOSTS, decodeFeed } from './feed';
type Source = {
  id: string;
  name: string;
  kind: string;
  state: string;
  revision: number;
  last_sync: number | null;
  last_error: string | null;
  canonical_url: string | null;
  feed: {
    hosts: string[];
    trust?: string;
    repository?: FeatherRepository;
    snapshot?: string;
  } | null;
  refresh_failures: number;
  next_refresh_at: number;
  refresh_lease_until: number;
  refresh_token: string | null;
};
type StoredRelease = {
  id: string;
  source_id: string;
  snapshot: string;
  metadata: Release;
};
export class CatalogRegistry {
  private flights = new Map<
    string,
    Promise<{
      count: number;
      snapshot: string;
    }>
  >();
  static readonly refreshIntervalMs = 15 * 60000;
  constructor(
    private db: Database,
    private now: () => number,
    private fetch: typeof fetchSafe = fetchSafe,
  ) {}
  async ensureBuiltIn(owner: string) {
    const created = await this.db.query<{
      id: string;
    }>(
      "INSERT INTO sources(id,owner_id,name,kind,state) SELECT $1,$2,'iApps Store','iapps','action_required' WHERE NOT EXISTS(SELECT 1 FROM sources WHERE owner_id=$2 AND kind='iapps') ON CONFLICT DO NOTHING RETURNING id",
      [id(), owner],
    );
    return { createdId: created.rows[0]?.id };
  }
  async ensureBuiltIns() {
    const users = (
      await this.db.query<{ id: string }>(
        'SELECT id FROM users WHERE deleted_at IS NULL AND blocked_at IS NULL',
      )
    ).rows;
    for (const user of users) await this.ensureBuiltIn(user.id);
  }
  private async source(owner: string, sourceId: string) {
    const r = await this.db.query<Source>('SELECT * FROM sources WHERE id=$1 AND owner_id=$2', [
      sourceId,
      owner,
    ]);
    if (!r.rows[0]) throw new Failure('NOT_FOUND', 404);
    return r.rows[0];
  }
  async add(
    owner: string,
    name: string,
    value: string,
    hosts: string[] = [],
    trustPublisher = false,
  ) {
    const url = validateUrl(value);
    if (!trustPublisher && !hosts.length) throw new Failure('SOURCE_TRUST_REQUIRED', 409);
    if (!name.trim() || name.length > 80) throw new Failure('INVALID_SOURCE_NAME');
    if (hosts.length) this.checkHosts(hosts);
    return this.db.transaction(async (tx) => {
      const user = await tx.query(
        'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',
        [owner],
      );
      if (!user.rows.length) throw new Failure('USER_UNAVAILABLE', 404);
      const prior = await tx.query<{
        id: string;
      }>('SELECT id FROM sources WHERE owner_id=$1 AND canonical_url=$2', [owner, url.href]);
      if (prior.rows[0]) return prior.rows[0];
      const quota = await tx.query<{
        count: number;
      }>(
        "SELECT COUNT(*)::integer AS count FROM sources WHERE owner_id=$1 AND state NOT IN('deleted','disabled')",
        [owner],
      );
      if (quota.rows[0].count >= 20) throw new Failure('SOURCE_QUOTA_EXCEEDED', 409);
      const sourceId = id();
      await tx.query(
        "INSERT INTO sources(id,owner_id,name,canonical_url,kind,state,feed) VALUES($1,$2,$3,$4,'gbox','action_required',$5)",
        [
          sourceId,
          owner,
          name.trim(),
          url.href,
          JSON.stringify({ hosts, trust: trustPublisher ? 'publisher' : 'explicit-hosts' }),
        ],
      );
      return { id: sourceId };
    });
  }
  private checkHosts(hosts: string[]) {
    if (
      !hosts.length ||
      hosts.length > 20 ||
      hosts.some((h) => !/^([a-z0-9-]+\.)+[a-z0-9-]+$/.test(h))
    )
      throw new Failure('INVALID_ARTIFACT_HOSTS');
    for (const h of hosts) validateUrl('https://' + h + '/');
  }
  async snapshot(
    owner: string,
    sourceId: string,
    input: unknown,
    hosts: string[],
    trustedBuiltIn = false,
    refreshToken?: string,
  ) {
    const source = await this.source(owner, sourceId);
    if (['deleted', 'disabled'].includes(source.state)) throw new Failure('SOURCE_DISABLED');
    if (source.kind !== 'gbox' && !(source.kind === 'iapps' && trustedBuiltIn))
      throw new Failure('SOURCE_METADATA_ONLY', 409);
    this.checkHosts(hosts);
    const { releases: normalized, repository } = normalizeCatalog(input);
    for (const r of normalized)
      if (r.url && !hosts.includes(new URL(r.url).hostname))
        throw new Failure('ARTIFACT_HOST_NOT_APPROVED');
    const revision = hash(
      JSON.stringify(repository ? { releases: normalized, repository } : normalized),
    );
    await this.db.transaction(async (tx) => {
      const r = await tx.query(
        "SELECT id FROM sources WHERE id=$1 AND owner_id=$2 AND state NOT IN('deleted','disabled') AND ($3::text IS NULL OR refresh_token=$3) FOR UPDATE",
        [sourceId, owner, refreshToken ?? null],
      );
      if (!r.rows.length) throw new Failure('NOT_FOUND', 404);
      await tx.query('DELETE FROM releases WHERE source_id=$1 AND owner_id=$2', [sourceId, owner]);
      for (const release of normalized)
        await tx.query(
          'INSERT INTO releases(id,source_id,owner_id,snapshot,metadata) VALUES($1,$2,$3,$4,$5)',
          [release.id, sourceId, owner, revision, JSON.stringify(release)],
        );
      await tx.query(
        "UPDATE sources SET state='ready',revision=revision+1,feed=$3,last_sync=$4,last_error=NULL,refresh_failures=0,next_refresh_at=$5,refresh_lease_until=0,refresh_token=NULL WHERE id=$1 AND owner_id=$2",
        [
          sourceId,
          owner,
          JSON.stringify({ hosts, trust: source.feed?.trust, repository, snapshot: revision }),
          this.now(),
          this.now() + CatalogRegistry.refreshIntervalMs,
        ],
      );
    });
    return { count: normalized.length, snapshot: revision };
  }
  /** Host discovery is authorized by the explicit publisher trust decision. Redirects
   * remain exact-host only; GitHub's public download adapter has fixed redirect hosts. */
  private discoveredHosts(input: unknown) {
    const hosts = new Set<string>();
    for (const r of normalizeCatalog(input).releases) {
      if (!r.url) continue;
      const url = validateUrl(r.url);
      hosts.add(url.hostname);
      if (url.hostname === 'github.com') {
        hosts.add('release-assets.githubusercontent.com');
        hosts.add('raw.githubusercontent.com');
      }
    }
    const result = [...hosts];
    if (!result.length) return ['github.com'];
    this.checkHosts(result);
    return result;
  }
  async refresh(owner: string, sourceId: string, manual = false) {
    const key = owner + ':' + sourceId;
    const previous = this.flights.get(key);
    if (previous) return previous;
    const flight = this.refreshOne(owner, sourceId, manual);
    this.flights.set(key, flight);
    try {
      return await flight;
    } finally {
      if (this.flights.get(key) === flight) this.flights.delete(key);
    }
  }
  private async refreshOne(owner: string, sourceId: string, manual: boolean) {
    const source = await this.source(owner, sourceId);
    if (source.state === 'disabled' || source.state === 'deleted')
      throw new Failure('SOURCE_DISABLED');
    const address = source.canonical_url ?? (source.kind === 'iapps' ? CURRENT_GBOX_URL : null);
    if (!address) throw new Failure('SOURCE_ACCESS_REQUIRED', 409);
    const lease = id(),
      now = this.now();
    const claimed = await this.db.query(
      "UPDATE sources SET refresh_token=$3,refresh_lease_until=$4 WHERE id=$1 AND owner_id=$2 AND state NOT IN('disabled','deleted') AND refresh_lease_until<=$5 AND ($6::boolean OR next_refresh_at<=$5) RETURNING id",
      [sourceId, owner, lease, now + 60000, now, manual],
    );
    if (!claimed.rows.length)
      throw new Failure(
        source.refresh_lease_until > now ? 'SOURCE_REFRESH_RUNNING' : 'SOURCE_REFRESH_BACKOFF',
        409,
      );
    try {
      const url = validateUrl(address),
        hosts = [url.hostname];
      if (url.hostname === 'github.com')
        hosts.push('release-assets.githubusercontent.com', 'raw.githubusercontent.com');
      const bytes = await this.fetch(url.href, {
        hosts,
        maxBytes: 8 * 1024 ** 2,
        timeoutMs: 30000,
      });
      const input = await decodeFeed(bytes, address);
      const packages =
        address === CURRENT_GBOX_URL
          ? CURRENT_PACKAGE_HOSTS
          : source.feed?.trust === 'publisher'
            ? this.discoveredHosts(input)
            : (source.feed?.hosts ?? [url.hostname]);
      return await this.snapshot(
        owner,
        sourceId,
        input,
        packages,
        source.kind === 'iapps' && address === CURRENT_GBOX_URL,
        lease,
      );
    } catch (error) {
      const reason = error instanceof Failure ? error.code : 'REMOTE_UNAVAILABLE';
      const backoff = Math.min(60 * 60000, 60000 * 2 ** Math.min(source.refresh_failures, 6));
      await this.db.query(
        "UPDATE sources SET last_error=$3,refresh_failures=refresh_failures+1,next_refresh_at=$4,refresh_token=NULL,refresh_lease_until=0,state=CASE WHEN state='ready' THEN state ELSE 'error' END WHERE id=$1 AND owner_id=$2 AND refresh_token=$5 AND state NOT IN('deleted','disabled')",
        [sourceId, owner, reason, this.now() + backoff, lease],
      );
      throw new Failure(reason, 502);
    }
  }
  /** A bounded server pass, independent of UI navigation. Claim leases coordinate
   * requests and workers; failed sources retain their owned last-good snapshot. */
  async refreshDue(limit = 4) {
    const rows = await this.db.query<{
      id: string;
      owner_id: string;
    }>(
      "SELECT s.id,s.owner_id FROM sources s JOIN users u ON u.id=s.owner_id WHERE s.state NOT IN('deleted','disabled') AND u.deleted_at IS NULL AND s.next_refresh_at<=$1 AND s.refresh_lease_until<=$1 ORDER BY s.next_refresh_at,s.id LIMIT $2",
      [this.now(), Math.min(4, Math.max(1, limit))],
    );
    return Promise.allSettled(rows.rows.map((r) => this.refresh(r.owner_id, r.id)));
  }
  async selection(owner: string, sourceId: string, releaseId: string, snapshot: string) {
    const source = await this.source(owner, sourceId);
    if (!['gbox', 'iapps'].includes(source.kind)) throw new Failure('SOURCE_METADATA_ONLY', 409);
    if (source.state !== 'ready') throw new Failure('SOURCE_DISABLED', 409);
    const result = await this.db.query<StoredRelease>(
      'SELECT * FROM releases WHERE id=$1 AND source_id=$2 AND owner_id=$3 AND snapshot=$4',
      [releaseId, sourceId, owner, snapshot],
    );
    if (!result.rows[0]) throw new Failure('RELEASE_UNAVAILABLE', 409);
    if (!result.rows[0].metadata.url) throw new Failure('SOURCE_METADATA_ONLY', 409);
    return {
      release: result.rows[0].metadata,
      hosts: source.feed?.hosts ?? [],
      sourceName: source.name,
      sourceKind: source.kind,
    };
  }
  async rename(owner: string, sourceId: string, name: string) {
    await this.source(owner, sourceId);
    if (!name.trim() || name.length > 80) throw new Failure('INVALID_SOURCE_NAME');
    await this.db.query('UPDATE sources SET name=$3 WHERE id=$1 AND owner_id=$2', [
      sourceId,
      owner,
      name.trim(),
    ]);
  }
  async disable(owner: string, sourceId: string) {
    await this.source(owner, sourceId);
    await this.db.query(
      "UPDATE sources SET state='disabled',feed=NULL,refresh_token=NULL,refresh_lease_until=0 WHERE id=$1 AND owner_id=$2",
      [sourceId, owner],
    );
  }
  async remove(owner: string, sourceId: string) {
    await this.source(owner, sourceId);
    await this.db.transaction(async (tx) => {
      await tx.query('DELETE FROM releases WHERE source_id=$1 AND owner_id=$2', [sourceId, owner]);
      await tx.query(
        "UPDATE sources SET state='deleted',feed=NULL,refresh_token=NULL,refresh_lease_until=0,canonical_url=NULL WHERE id=$1 AND owner_id=$2",
        [sourceId, owner],
      );
    });
  }
}
