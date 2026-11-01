import type { Database } from '../shared/database';
import type { ClientReleasePort, ClientReleaseStatus } from '../shared/client-release';
import type { JobsActions } from '../signing/jobs-actions';
import type { ReceiveUpload } from './receive-upload';
import type { Tickets } from '../library/tickets';
import { Failure, hash, id } from '../shared';

type Options = {
  db: Database;
  release: ClientReleasePort;
  jobs: Pick<JobsActions, 'beginSubmission'>;
  receive: Pick<ReceiveUpload, 'run'>;
  authorization: { requireUpload(owner: string): Promise<void> };
  devices: { checkRegistered(owner: string, device: string): Promise<unknown> };
  tickets: Pick<Tickets, 'issueDetails'>;
  now: () => number;
  ensureSigningReady?: (owner: string) => Promise<unknown>;
};
type Operation = {
  id: string;
  job_id: string;
  device_id: string;
  release_sha256: string;
  version: string | null;
};
export type ClientInstallation = {
  operationId: string;
  jobId: string;
  state: string;
  reason?: string;
  updatedAt?: number;
  artifactId?: string;
  version?: string;
};
const authorized = `FROM client_installations i
 JOIN signing_jobs j ON j.id=i.job_id AND j.owner_id=i.owner_id AND j.device_id=i.device_id
 JOIN uploads u ON u.id=j.upload_id AND u.owner_id=j.owner_id
 JOIN apple_connections c ON c.id=j.connection_id AND c.owner_id=j.owner_id AND c.generation=j.connection_generation AND c.state='ready'
 JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id AND d.connection_id=j.connection_id AND d.connection_generation=c.generation AND d.status='ready'
 WHERE i.id=$1 AND i.owner_id=$2 AND u.provenance->>'kind'='isign-client' AND u.provenance->>'sha256'=i.release_sha256
 AND (j.state IN('receiving','failed','cancelled') OR u.digest=i.release_sha256)`;
/** Only this scenario can choose the fixed, operator-pinned web installation source. */
export class ClientInstallations {
  constructor(private options: Options) {}
  async assertReady() {
    const row = (
      await this.options.db.query<{ ready: boolean }>(
        "SELECT count(*)=9 AS ready FROM information_schema.columns WHERE table_schema='public' AND table_name='client_installations' AND column_name IN('id','owner_id','request_key','job_id','device_id','release_sha256','version','receive_started_at','created_at')",
      )
    ).rows[0];
    if (!row?.ready) throw new Failure('CLIENT_INSTALLER_MIGRATION_REQUIRED', 503);
  }
  async release(): Promise<ClientReleaseStatus> {
    try {
      await this.assertReady();
    } catch (error) {
      if (!(error instanceof Failure)) throw error;
      return { name: 'iSign Client', available: false, reason: error.code };
    }
    return this.options.release.status();
  }
  async begin(
    owner: string,
    input: { deviceId: string; key: string },
  ): Promise<ClientInstallation> {
    if (!/^[A-Za-z0-9_-]{1,100}$/.test(input.key) || !input.deviceId || input.deviceId.length > 100)
      throw new Failure('INVALID_REQUEST');
    const o = this.options;
    await this.assertReady();
    await o.authorization.requireUpload(owner);
    await o.devices.checkRegistered(owner, input.deviceId);
    await o.ensureSigningReady?.(owner);
    const source = await o.release.open();
    const previous = (
      await o.db.query<Operation>(
        'SELECT * FROM client_installations WHERE owner_id=$1 AND request_key=$2',
        [owner, input.key],
      )
    ).rows[0];
    if (
      previous &&
      (previous.device_id !== input.deviceId || previous.release_sha256 !== source.digest)
    )
      throw new Failure('IDEMPOTENCY_BINDING_MISMATCH', 409);
    const provenance = { kind: 'isign-client', sha256: source.digest };
    const submission = await o.jobs.beginSubmission(owner, {
      deviceId: input.deviceId,
      key: 'client_' + hash(input.key),
      name: 'iSign Client.ipa',
      source: 'upload',
      provenance,
    });
    // A crash before insertion is recovered via the same durable job idempotency key.
    await o.db.query(
      'INSERT INTO client_installations(id,owner_id,request_key,job_id,device_id,release_sha256,version,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(owner_id,request_key) DO NOTHING',
      [
        id(),
        owner,
        input.key,
        submission.jobId,
        input.deviceId,
        source.digest,
        source.version ?? null,
        o.now(),
      ],
    );
    const operation = (
      await o.db.query<Operation>(
        'SELECT * FROM client_installations WHERE owner_id=$1 AND request_key=$2',
        [owner, input.key],
      )
    ).rows[0];
    if (
      operation.job_id !== submission.jobId ||
      operation.release_sha256 !== source.digest ||
      operation.device_id !== input.deviceId
    )
      throw new Failure('IDEMPOTENCY_BINDING_MISMATCH', 409);
    // The claim is persisted before consuming bytes. A second request only observes the job.
    const claimed = await o.db.query(
      `UPDATE client_installations i SET receive_started_at=$3 WHERE i.id=$1 AND i.owner_id=$2 AND receive_started_at IS NULL AND EXISTS(SELECT 1 FROM jobs j WHERE j.id=i.job_id AND j.owner_id=i.owner_id AND j.state='receiving') RETURNING id`,
      [operation.id, owner, o.now()],
    );
    if (claimed.rows.length) {
      try {
        await o.receive.run(owner, submission.uploadId, source.bytes, undefined, {
          expectedDigest: source.digest,
          provenance,
        });
      } catch {
        /* ReceiveUpload records the terminal failure and cleans up partial storage. */
      }
    }
    return this.view(owner, operation.id);
  }
  async view(owner: string, operation: string): Promise<ClientInstallation> {
    await this.assertReady();
    const row = (
      await this.options.db.query<
        Operation & {
          state: string;
          reason: string | null;
          updated_at: number;
          artifact_id: string | null;
        }
      >(
        `SELECT i.*,j.state,j.reason,j.updated_at,
        (SELECT a.id FROM signing_artifacts a WHERE a.job_id=j.id AND a.owner_id=j.owner_id
          AND a.device_id=j.device_id AND a.connection_id=j.connection_id AND a.connection_owner_id=j.connection_owner_id
          AND a.access_grant_id IS NOT DISTINCT FROM j.access_grant_id AND a.access_grant_generation IS NOT DISTINCT FROM j.access_grant_generation
          AND j.state='ready' AND a.verified AND a.expires_at>$3 AND a.valid_until>$3
          AND (a.metadata->>'generation')::integer=c.generation ORDER BY a.created_at DESC,a.id LIMIT 1) AS artifact_id
        ${authorized}`,
        [operation, owner, this.options.now()],
      )
    ).rows[0];
    if (!row) throw new Failure('NOT_FOUND', 404);
    return {
      operationId: row.id,
      jobId: row.job_id,
      state: row.state === 'ready' && !row.artifact_id ? 'failed' : row.state,
      ...(row.state === 'ready' && !row.artifact_id
        ? { reason: 'CLIENT_INSTALL_ARTIFACT_UNAVAILABLE' }
        : row.reason
          ? { reason: row.reason }
          : {}),
      updatedAt: Number(row.updated_at),
      ...(row.version ? { version: row.version } : {}),
      ...(row.artifact_id ? { artifactId: row.artifact_id } : {}),
    };
  }
  async ticket(owner: string, operation: string) {
    const current = await this.view(owner, operation);
    if (!current.artifactId) throw new Failure('CLIENT_INSTALL_NOT_READY', 409);
    return this.options.tickets.issueDetails(owner, current.artifactId);
  }
}
