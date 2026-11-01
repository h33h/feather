import { mkdir, chmod, open, unlink, rename, readdir, lstat, statfs } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure, id } from '../shared/index';
import type { UploadOptions, FileReadHandle } from './storage-contract';
export const PERSONAL_POLICY = {
  maxFile: 1024 ** 3,
  ownerQuota: 2 * 1024 ** 3,
  globalQuota: 3 * 1024 ** 3,
  minimumFree: 8 * 1024 ** 3,
  retentionMs: 86400000,
};
type Row = {
  id: string;
  owner_id: string;
  kind: 'upload' | 'artifact';
  object_key: string | null;
  size: number;
  state: string;
  job_id: string | null;
  lease_expires: number;
  created_at: number;
};
export class PersonalObjects {
  private ready = false;
  private readers = new Map<string, number>();
  private readerClosers = new Map<string, Set<() => Promise<void>>>();
  private writers = new Set<string>();
  private writerStops = new Map<string, () => void>();
  private writerDone = new Map<string, Promise<void>>();
  private recovering: Promise<void> | undefined;
  constructor(
    public db: Database,
    public directory: string,
    public now: () => number,
    public policy = PERSONAL_POLICY,
  ) {}
  file(kind: Row['kind'], key: string) {
    if (!/^[a-f0-9-]{36}\.ipa(?:\.partial)?$/.test(key)) throw new Failure('INVALID_OBJECT_KEY');
    return path.join(this.directory, kind, key);
  }
  async free(required = 0) {
    const info = await statfs(this.directory);
    if (info.bavail * info.bsize < this.policy.minimumFree + required)
      throw new Failure('DISK_RESERVE_REQUIRED', 409);
  }
  private async lock(tx: QueryDatabase) {
    await tx.query('SELECT id FROM personal_state WHERE id=1 FOR UPDATE');
  }
  async reserve(owner: string, kind: Row['kind'], job?: string) {
    if (!this.ready) throw new Failure('PERSONAL_STORAGE_RECOVERY_REQUIRED', 503);
    await this.free(this.policy.maxFile);
    const objectId = id();
    return this.db.transaction(async (tx) => {
      await this.lock(tx);
      const user = await tx.query(
        'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
        [owner],
      );
      if (!user.rows.length) throw new Failure('ACCOUNT_DELETED', 403);
      if (job) {
        const existing = await tx.query<Row>(
          'SELECT * FROM personal_objects WHERE job_id=$1 AND owner_id=$2',
          [job, owner],
        );
        if (existing.rows[0]) return existing.rows[0].id;
      }
      const totals = await tx.query<{
        total: number;
        owned: number;
      }>(
        'SELECT COALESCE(SUM(size),0) AS total,COALESCE(SUM(CASE WHEN owner_id=$1 THEN size ELSE 0 END),0) AS owned FROM personal_objects',
        [owner],
      );
      if (
        Number(totals.rows[0].total) + this.policy.maxFile > this.policy.globalQuota ||
        Number(totals.rows[0].owned) + this.policy.maxFile > this.policy.ownerQuota
      )
        throw new Failure('QUOTA_EXCEEDED', 409);
      await tx.query(
        "INSERT INTO personal_objects(id,owner_id,kind,size,state,job_id,lease_expires,created_at) VALUES($1,$2,$3,$4,'reserved',$5,$6,$7)",
        [objectId, owner, kind, this.policy.maxFile, job ?? null, this.now() + 1800000, this.now()],
      );
      return objectId;
    });
  }
  async write(
    objectId: string,
    owner: string,
    kind: Row['kind'],
    key: string,
    input: AsyncIterable<Uint8Array>,
    signal?: AbortSignal,
  ) {
    this.writers.add(objectId);
    const controller = new AbortController();
    this.writerStops.set(objectId, () => controller.abort());
    let finished!: () => void;
    this.writerDone.set(
      objectId,
      new Promise<void>((resolve) => {
        finished = resolve;
      }),
    );
    try {
      return await this.writeObject(
        objectId,
        owner,
        kind,
        key,
        input,
        signal ? AbortSignal.any([signal, controller.signal]) : controller.signal,
      );
    } finally {
      this.writers.delete(objectId);
      this.writerStops.delete(objectId);
      try {
        const pending = await this.db.query(
          "SELECT id FROM personal_objects WHERE id=$1 AND state='deleting'",
          [objectId],
        );
        if (pending.rows.length) await this.remove(objectId);
      } finally {
        this.writerDone.delete(objectId);
        finished();
      }
    }
  }
  private async writeObject(
    objectId: string,
    owner: string,
    kind: Row['kind'],
    key: string,
    input: AsyncIterable<Uint8Array>,
    signal?: AbortSignal,
  ) {
    const claimed = await this.db.query(
      "UPDATE personal_objects SET object_key=$4,state='writing',lease_expires=$5 WHERE id=$1 AND owner_id=$2 AND kind=$3 AND state='reserved' RETURNING id",
      [objectId, owner, kind, key, this.now() + 120000],
    );
    if (!claimed.rows.length) throw new Failure('OBJECT_RESERVATION_LOST', 409);
    let lost = false;
    let interrupt!: () => void;
    const interruption = new Promise<never>((_, reject) => {
      interrupt = () => {
        lost = true;
        reject(new Failure('UPLOAD_INTERRUPTED'));
      };
    });
    void interruption.catch(() => {});
    signal?.addEventListener('abort', interrupt, { once: true });
    if (signal?.aborted) interrupt();
    const iterator = input[Symbol.asyncIterator]();
    const timer = setInterval(() => {
      void this.db
        .query(
          "UPDATE personal_objects SET lease_expires=$3 WHERE id=$1 AND owner_id=$2 AND state='writing' RETURNING id",
          [objectId, owner, this.now() + 120000],
        )
        .then((r) => {
          if (!r.rows.length) lost = true;
        })
        .catch(() => {
          lost = true;
        });
    }, 30000);
    timer.unref();
    const partial = this.file(kind, key + '.partial');
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    try {
      handle = await open(
        partial,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      const sha = createHash('sha256');
      let size = 0;
      while (true) {
        const next = await Promise.race([iterator.next(), interruption]);
        if (next.done) break;
        const chunk = next.value;
        if (signal?.aborted || lost) throw new Failure('UPLOAD_INTERRUPTED');
        await this.free();
        if (
          !(
            await this.db.query(
              'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL',
              [owner],
            )
          ).rows.length
        )
          throw new Failure('ACCOUNT_DELETED', 403);
        size += chunk.byteLength;
        if (size > this.policy.maxFile)
          throw new Failure(
            kind === 'upload' ? 'FILE_TOO_LARGE' : 'SIGNED_ARTIFACT_TOO_LARGE',
            413,
          );
        sha.update(chunk);
        await handle.writeFile(chunk);
      }
      if (!size) throw new Failure('EMPTY_FILE');
      if (signal?.aborted || lost) throw new Failure('UPLOAD_INTERRUPTED');
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(partial, this.file(kind, key));
      await this.syncDirectory(kind);
      const persisted = await this.db.query(
        "UPDATE personal_objects SET size=$3,state='live',lease_expires=$4 WHERE id=$1 AND owner_id=$2 AND state='writing' AND lease_expires>$5 AND EXISTS(SELECT 1 FROM users WHERE id=$2 AND deleted_at IS NULL AND blocked_at IS NULL) RETURNING id",
        [objectId, owner, size, this.now() + 15 * 60000, this.now()],
      );
      if (!persisted.rows.length) throw new Failure('OBJECT_RESERVATION_LOST', 409);
      return { size, digest: sha.digest('hex') };
    } catch (error) {
      await handle?.close();
      await this.remove(objectId);
      if (error instanceof Failure) throw error;
      throw new Failure('UPLOAD_INTERRUPTED');
    } finally {
      clearInterval(timer);
      signal?.removeEventListener('abort', interrupt);
      // Upstream return can wait forever behind its pending next(). Never retain our FD for it.
      void iterator.return?.().catch(() => {});
    }
  }
  private async syncDirectory(kind: Row['kind']) {
    const handle = await open(
      path.join(this.directory, kind),
      constants.O_RDONLY | constants.O_NOFOLLOW,
    );
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  }
  async remove(objectId: string) {
    const result = await this.db.query<Row>(
      "UPDATE personal_objects SET state='deleting' WHERE id=$1 RETURNING *",
      [objectId],
    );
    const row = result.rows[0];
    if (!row) return;
    if (this.writers.has(row.id)) return;
    if (row.object_key) {
      if ((this.readers.get(row.kind + ':' + row.object_key) ?? 0) > 0) return;
      for (const suffix of ['.partial', ''])
        await unlink(this.file(row.kind, row.object_key + suffix)).catch((error) => {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        });
      await this.syncDirectory(row.kind);
    }
    await this.db.query("DELETE FROM personal_objects WHERE id=$1 AND state='deleting'", [
      objectId,
    ]);
  }
  async expireObject(objectId: string, kind: Row['kind'], key: string) {
    // Fence new readers before closing every existing descriptor and stream.
    await this.db.query(
      "UPDATE personal_objects SET state='deleting' WHERE id=$1 AND object_key=$2 AND kind=$3",
      [objectId, key, kind],
    );
    this.writerStops.get(objectId)?.();
    await this.writerDone.get(objectId);
    await Promise.all(
      [...(this.readerClosers.get(kind + ':' + key) ?? [])].map((close) => close()),
    );
    await this.remove(objectId);
  }
  async handle(
    kind: Row['kind'],
    key: string,
    guard: () => Promise<void>,
  ): Promise<FileReadHandle> {
    const readerKey = kind + ':' + key;
    this.readers.set(readerKey, (this.readers.get(readerKey) ?? 0) + 1);
    let handle: Awaited<ReturnType<typeof open>> | undefined;
    let closed = false;
    const streams = new Set<Readable>();
    const close = async () => {
      if (closed) return;
      closed = true;
      this.readerClosers.get(readerKey)?.delete(close);
      if (!this.readerClosers.get(readerKey)?.size) this.readerClosers.delete(readerKey);
      for (const stream of streams) stream.destroy();
      try {
        await handle?.close();
      } finally {
        const remaining = (this.readers.get(readerKey) ?? 1) - 1;
        if (remaining) this.readers.set(readerKey, remaining);
        else this.readers.delete(readerKey);
        const pending = await this.db.query<{
          id: string;
        }>("SELECT id FROM personal_objects WHERE kind=$1 AND object_key=$2 AND state='deleting'", [
          kind,
          key,
        ]);
        if (!remaining && pending.rows[0]) await this.remove(pending.rows[0].id);
      }
    };
    const closers = this.readerClosers.get(readerKey) ?? new Set<() => Promise<void>>();
    closers.add(close);
    this.readerClosers.set(readerKey, closers);
    try {
      await guard();
      handle = await open(this.file(kind, key), constants.O_RDONLY | constants.O_NOFOLLOW);
      if (closed) {
        await handle.close();
        throw new Failure('NOT_FOUND', 404);
      }
      await guard();
    } catch (error) {
      await close();
      throw error;
    }
    return {
      stat: async () => {
        await guard();
        if (closed) throw new Failure('NOT_FOUND', 404);
        return handle!.stat();
      },
      close,
      createReadStream: (options = {}) => {
        const stream = Readable.from(
          (async function* () {
            try {
              let position = options.start ?? 0;
              const end = options.end ?? Number.MAX_SAFE_INTEGER;
              while (position <= end) {
                await guard();
                if (closed) throw new Failure('NOT_FOUND', 404);
                const buffer = Buffer.alloc(Math.min(65536, end - position + 1));
                const { bytesRead } = await handle!.read(buffer, 0, buffer.length, position);
                await guard();
                if (!bytesRead) break;
                position += bytesRead;
                yield buffer.subarray(0, bytesRead);
              }
            } finally {
              if (options.autoClose !== false) await close();
            }
          })(),
        );
        streams.add(stream);
        stream.once('close', () => streams.delete(stream));
        if (closed) stream.destroy();
        return stream;
      },
    };
  }
  async recover() {
    if (this.recovering) return this.recovering;
    const work = this.reconcile();
    this.recovering = work;
    try {
      await work;
    } finally {
      this.recovering = undefined;
    }
  }
  private async reconcile() {
    this.ready = false;
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    if (
      !(await lstat(this.directory)).isDirectory() ||
      (await lstat(this.directory)).isSymbolicLink()
    )
      throw new Failure('PERSONAL_STORAGE_UNSAFE_FILE', 503);
    await chmod(this.directory, 0o700);
    for (const kind of ['upload', 'artifact'] as const) {
      await mkdir(path.join(this.directory, kind), { recursive: true, mode: 0o700 });
      const directoryInfo = await lstat(path.join(this.directory, kind));
      if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink())
        throw new Failure('PERSONAL_STORAGE_UNSAFE_FILE', 503);
      await chmod(path.join(this.directory, kind), 0o700);
      const files = await readdir(path.join(this.directory, kind));
      for (const key of files) {
        if (!/^[a-f0-9-]{36}\.ipa(?:\.partial)?$/.test(key))
          throw new Failure('PERSONAL_STORAGE_UNKNOWN_FILE', 503);
        const info = await lstat(this.file(kind, key));
        if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0)
          throw new Failure('PERSONAL_STORAGE_UNSAFE_FILE', 503);
        const known = await this.db.query(
          'SELECT id FROM personal_objects WHERE kind=$1 AND object_key=$2',
          [kind, key.replace(/\.partial$/, '')],
        );
        if (!known.rows.length) {
          const reference = await this.db.query(
            kind === 'upload'
              ? 'SELECT id FROM uploads WHERE object_key=$1'
              : 'SELECT id FROM artifacts WHERE object_key=$1',
            [key.replace(/\.partial$/, '')],
          );
          if (reference.rows.length) throw new Failure('PERSONAL_STORAGE_STATE_INVALID', 503);
          await unlink(this.file(kind, key));
          await this.syncDirectory(kind);
        }
      }
    }
    const rows = await this.db.query<Row>('SELECT * FROM personal_objects');
    for (const row of rows.rows) {
      if (row.state === 'deleting') {
        await this.remove(row.id);
        continue;
      }
      if (['writing', 'reserved'].includes(row.state) && Number(row.lease_expires) <= this.now()) {
        const running = row.job_id
          ? (
              await this.db.query(
                "SELECT id FROM jobs WHERE id=$1 AND owner_id=$2 AND state IN('queued','analyzing','provisioning','signing','verifying')",
                [row.job_id, row.owner_id],
              )
            ).rows.length
          : 0;
        if (!running) await this.remove(row.id);
      }
      if (row.state === 'live' && row.object_key) {
        if (
          Number(row.lease_expires) <= this.now() &&
          !(
            await this.db.query(
              row.kind === 'upload'
                ? 'SELECT id FROM uploads WHERE object_key=$1'
                : 'SELECT id FROM artifacts WHERE object_key=$1',
              [row.object_key],
            )
          ).rows.length
        ) {
          await this.remove(row.id);
          continue;
        }
        try {
          const info = await lstat(this.file(row.kind, row.object_key));
          if (info.size !== Number(row.size))
            throw new Failure('PERSONAL_STORAGE_STATE_INVALID', 503);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
          await this.remove(row.id);
          if (row.kind === 'upload')
            await this.db.query(
              "UPDATE uploads SET status='expired',expires_at=$2 WHERE object_key=$1",
              [row.object_key, this.now()],
            );
          else
            await this.db.query('UPDATE artifacts SET verified=false WHERE object_key=$1', [
              row.object_key,
            ]);
        }
      }
    }
    this.ready = true;
  }
}
export class PersonalStorage {
  constructor(public objects: PersonalObjects) {}
  async upload(
    owner: string,
    name: string,
    input: AsyncIterable<Uint8Array>,
    options: UploadOptions = {},
  ) {
    if (!/\.ipa$/i.test(name) || name.length > 180 || /[\x00-\x1f/\\]/.test(name))
      throw new Failure('INVALID_FILE_NAME');
    if (!options.uploadId || !options.jobId) throw new Failure('RECEIVING_JOB_REQUIRED', 409);
    const uploadId = options.uploadId,
      key = uploadId + '.ipa';
    const admitted = await this.objects.db.query(
      "SELECT j.id FROM signing_jobs j JOIN apple_connections c ON c.id=j.connection_id AND c.owner_id=j.owner_id JOIN uploads u ON u.id=j.upload_id AND u.owner_id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.upload_id=$3 AND j.state='receiving' AND c.state='ready' AND c.generation=j.connection_generation AND u.delete_requested_at IS NULL AND u.status='receiving'",
      [options.jobId, owner, uploadId],
    );
    if (!admitted.rows.length) throw new Failure('SIGNING_INPUT_NOT_READY', 409);
    const reservation = await this.objects.reserve(owner, 'upload');
    try {
      const stored = await this.objects.write(
        reservation,
        owner,
        'upload',
        key,
        input,
        options.signal,
      );
      if (options.expectedDigest && stored.digest !== options.expectedDigest.toLowerCase())
        throw new Failure('CHECKSUM_MISMATCH');
      const persisted = await this.objects.db.query(
        "UPDATE uploads u SET size=$4,digest=$5,status='ready',provenance=COALESCE($6,provenance),expires_at=$7 WHERE id=$1 AND owner_id=$2 AND status='receiving' AND delete_requested_at IS NULL AND EXISTS(SELECT 1 FROM signing_jobs j JOIN apple_connections c ON c.id=j.connection_id AND c.owner_id=j.owner_id WHERE j.id=$3 AND j.upload_id=u.id AND j.state='receiving' AND c.state='ready' AND c.generation=j.connection_generation) RETURNING id",
        [
          uploadId,
          owner,
          options.jobId,
          stored.size,
          stored.digest,
          options.provenance ? JSON.stringify(options.provenance) : null,
          Number.MAX_SAFE_INTEGER,
        ],
      );
      if (!persisted.rows.length) throw new Failure('SIGNING_INPUT_NOT_READY', 409);
      return { id: uploadId, ...stored };
    } catch (error) {
      await this.objects.remove(reservation);
      throw error;
    }
  }
  async read(owner: string, upload: string) {
    const load = async () => {
      const r = await this.objects.db.query<{
        object_key: string;
      }>(
        "SELECT x.object_key FROM uploads x JOIN users u ON u.id=x.owner_id JOIN personal_objects p ON p.object_key=x.object_key AND p.owner_id=x.owner_id WHERE x.id=$1 AND x.owner_id=$2 AND x.expires_at>$3 AND x.status<>'expired' AND x.delete_requested_at IS NULL AND u.deleted_at IS NULL AND blocked_at IS NULL AND p.state='live'",
        [upload, owner, this.objects.now()],
      );
      if (!r.rows[0]) throw new Failure('NOT_FOUND', 404);
      return r.rows[0].object_key;
    };
    const key = await load();
    return this.objects.handle('upload', key, async () => {
      if ((await load()) !== key) throw new Failure('NOT_FOUND', 404);
    });
  }
  async recoverInterrupted() {
    await this.objects.recover();
    await this.objects.db.query(
      "UPDATE imports SET state=CASE WHEN upload_id IS NULL THEN 'failed' ELSE 'uploaded' END,attempt_token=NULL WHERE state='downloading' AND lease_expires<=$1",
      [this.objects.now()],
    );
  }
  async cleanup() {
    const rows = await this.objects.db.query<{
      id: string;
      object_id: string;
    }>(
      "SELECT u.id,p.id AS object_id FROM uploads u JOIN personal_objects p ON p.object_key=u.object_key WHERE (u.expires_at<=$1 OR u.delete_requested_at IS NOT NULL) AND u.status<>'expired'",
      [this.objects.now()],
    );
    for (const row of rows.rows) {
      const object = (
        await this.objects.db.query<{ object_key: string }>(
          'SELECT object_key FROM personal_objects WHERE id=$1',
          [row.object_id],
        )
      ).rows[0];
      if (object?.object_key)
        await this.objects.expireObject(row.object_id, 'upload', object.object_key);
      else await this.objects.remove(row.object_id);
      await this.objects.db.query("UPDATE uploads SET status='expired' WHERE id=$1", [row.id]);
    }
  }
}
export class PersonalArtifacts {
  static readonly availabilityMs = 1800000;
  constructor(public objects: PersonalObjects) {}
  get retentionMs() {
    return PersonalArtifacts.availabilityMs;
  }
  async published(tx: QueryDatabase, owner: string, job: string) {
    await tx.query(
      'UPDATE uploads SET delete_requested_at=$3 WHERE owner_id=$1 AND id IN(SELECT upload_id FROM jobs WHERE id=$2 AND owner_id=$1)',
      [owner, job, this.objects.now()],
    );
  }
  async confirmStored(tx: QueryDatabase, key: string, owner: string, size: number) {
    if (
      !(
        await tx.query(
          "SELECT id FROM personal_objects WHERE object_key=$1 AND owner_id=$2 AND size=$3 AND state='live' AND kind='artifact' FOR UPDATE",
          [key, owner, size],
        )
      ).rows.length
    )
      throw new Failure('ARTIFACT_STORAGE_LEASE_EXPIRED', 409);
  }
  /** Caller must first confirm retirement of the executor for this attempt. */
  async discardAttempt(owner: string, job: string) {
    const rows = (
      await this.objects.db.query<Row>(
        "SELECT p.* FROM personal_objects p WHERE p.owner_id=$1 AND p.job_id=$2 AND p.kind='artifact' AND NOT EXISTS(SELECT 1 FROM artifacts a WHERE a.owner_id=p.owner_id AND a.object_key=p.object_key)",
        [owner, job],
      )
    ).rows;
    for (const row of rows) {
      if (row.object_key) await this.objects.expireObject(row.id, 'artifact', row.object_key);
      else await this.objects.remove(row.id);
    }
  }
  async reserveJob(owner: string, job: string) {
    return this.objects.reserve(owner, 'artifact', job);
  }
  async put(key: string, body: AsyncIterable<Uint8Array>, owner?: string) {
    if (!owner) throw new Failure('ARTIFACT_OWNER_REQUIRED');
    const rows = await this.objects.db.query<Row>(
      "SELECT p.* FROM personal_objects p JOIN jobs j ON j.id=p.job_id AND j.owner_id=p.owner_id WHERE p.owner_id=$1 AND p.kind='artifact' AND p.state='reserved' AND j.state IN('analyzing','provisioning','signing','verifying')",
      [owner],
    );
    if (rows.rows.length !== 1) throw new Failure('ARTIFACT_RESERVATION_REQUIRED', 409);
    return this.objects.write(rows.rows[0].id, owner, 'artifact', key, body);
  }
  async delete(key: string, owner?: string) {
    const rows = await this.objects.db.query<{ id: string }>(
      "SELECT id FROM personal_objects WHERE object_key=$1 AND kind='artifact' AND ($2::text IS NULL OR owner_id=$2)",
      [key, owner ?? null],
    );
    for (const row of rows.rows) await this.objects.expireObject(row.id, 'artifact', key);
  }
  async open(key: string) {
    const guard = async () => {
      const row = await this.objects.db.query(
        `WITH authorized AS MATERIALIZED (SELECT a.* FROM signing_artifacts a WHERE a.object_key=$1)
 SELECT a.id FROM authorized a JOIN personal_objects p ON p.object_key=a.object_key AND p.owner_id=a.owner_id
 JOIN connections c ON c.id=a.connection_id AND c.owner_id=a.connection_owner_id
 JOIN devices d ON d.id=a.device_id AND d.owner_id=a.owner_id AND d.connection_id=a.connection_id AND d.connection_owner_id=a.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM a.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM a.access_grant_generation
 JOIN jobs j ON j.id=a.job_id AND j.owner_id=a.owner_id
 WHERE a.verified AND a.expires_at>$2 AND a.valid_until>$2 AND p.state='live' AND c.state='ready' AND c.generation=(a.metadata->>'generation')::integer AND d.status='ready' AND d.enrollment_verified_at IS NOT NULL AND d.connection_generation=c.generation AND j.state='ready'`,
        [key, this.objects.now()],
      );
      if (!row.rows.length) throw new Failure('ARTIFACT_NOT_FOUND', 404);
    };
    return this.objects.handle('artifact', key, guard);
  }
  async cleanup() {
    const rows = await this.objects.db.query<Row>(
      "SELECT p.* FROM personal_objects p LEFT JOIN artifacts a ON a.object_key=p.object_key LEFT JOIN jobs j ON j.id=p.job_id LEFT JOIN users u ON u.id=p.owner_id LEFT JOIN apple_connections c ON c.id=a.connection_id AND c.owner_id=a.owner_id WHERE p.kind='artifact' AND (u.deleted_at IS NOT NULL OR u.blocked_at IS NOT NULL OR a.expires_at<=$1 OR a.valid_until<=$1 OR a.verified=false OR (a.id IS NOT NULL AND (c.id IS NULL OR c.state<>'ready' OR (a.metadata->>'generation')::integer<>c.generation)) OR (a.id IS NULL AND (p.lease_expires<=$1 OR p.state='reserved') AND (j.id IS NULL OR j.state NOT IN('queued','analyzing','provisioning','signing','verifying'))))",
      [this.objects.now()],
    );
    for (const row of rows.rows) {
      if (row.object_key) {
        await this.objects.db.query('UPDATE artifacts SET verified=false WHERE object_key=$1', [
          row.object_key,
        ]);
        await this.objects.db.query(
          "UPDATE tickets SET state='revoked' WHERE artifact_id IN(SELECT id FROM artifacts WHERE object_key=$1)",
          [row.object_key],
        );
        await this.objects.expireObject(row.id, 'artifact', row.object_key);
      } else await this.objects.remove(row.id);
    }
  }
}
