import type { Database, QueryDatabase } from '../shared/database';
import { Failure, token, id, hash } from '../shared/index';
import { lockAuthority } from '../apple/access-lifecycle';
import { classifyJobFailure } from './retry-policy';
import type { ExecutorGrant } from '../shared/runner-contracts';
import { canonicalReport } from '../shared/canonical-json';

type Lease = Pick<ExecutorGrant, 'ownerId' | 'jobId' | 'leaseToken'>;
type FinalState = 'queued' | 'ready' | 'failed' | 'cancelled';
const active = "('receiving','queued','analyzing','provisioning','signing','verifying')";
const working = "('analyzing','provisioning','signing','verifying')";
const eligible = `EXISTS(SELECT 1 FROM signing_jobs current
 JOIN signing_devices d ON d.id=current.device_id AND d.owner_id=current.owner_id
 JOIN apple_connections c ON c.id=current.connection_id AND c.owner_id=current.owner_id
 JOIN uploads u ON u.id=current.upload_id AND u.owner_id=current.owner_id
 WHERE current.id=j.id AND c.state='ready' AND d.status='ready'
 AND c.generation=current.connection_generation AND d.connection_generation=c.generation
 AND u.status IN('uploaded','ready') AND u.expires_at>$3 AND u.delete_requested_at IS NULL)`;

type DeviceBinding = {
  deviceId: string;
  deviceName: string;
  connectionId: string;
  generation: number;
  connectionOwnerId: string;
  grantId: string | null;
  grantGeneration: number | null;
};

export class JobLifecycle {
  constructor(
    public db: Database,
    private clock: () => number,
    private kickoff?: (owner: string, job: string, device: string) => Promise<unknown>,
  ) {}
  get now() {
    return this.clock();
  }
  private notify(owner: string, job: string, device: string) {
    if (this.kickoff)
      void Promise.resolve()
        .then(() => this.kickoff!(owner, job, device))
        .catch(() => {});
  }
  private async owner(tx: QueryDatabase, owner: string) {
    if (
      !(
        await tx.query(
          'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
          [owner],
        )
      ).rows.length
    )
      throw new Failure('USER_UNAVAILABLE', 404);
  }
  private async device(tx: QueryDatabase, owner: string, deviceId: string) {
    const devices = await tx.query<DeviceBinding>(
      `SELECT d.id AS "deviceId",d.name AS "deviceName",c.id AS "connectionId",c.generation,c.connection_owner_id AS "connectionOwnerId",c.access_grant_id AS "grantId",c.access_grant_generation AS "grantGeneration"
       FROM signing_devices d JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=d.owner_id
       WHERE d.owner_id=$1 AND d.id=$2 AND d.status='ready' AND c.state='ready' AND d.connection_generation=c.generation`,
      [owner, deviceId],
    );
    if (!devices.rows.length) throw new Failure('DEVICE_SELECTION_REQUIRED', 409);
    return devices.rows[0];
  }
  private async vacant(tx: QueryDatabase, owner: string) {
    if (
      (await tx.query('SELECT id FROM jobs WHERE owner_id=$1 AND state IN' + active, [owner])).rows
        .length
    )
      throw new Failure('ACTIVE_JOB_EXISTS', 409);
  }
  private key(key: string) {
    if (!/^[A-Za-z0-9_-]{1,100}$/.test(key)) throw new Failure('INVALID_IDEMPOTENCY_KEY');
  }
  async beginClientInstallation(
    owner: string,
    input: { key: string; deviceId: string; releaseSha256: string; version?: string },
  ) {
    this.key(input.key);
    if (
      !input.deviceId ||
      input.deviceId.length > 100 ||
      !/^[a-f0-9]{64}$/.test(input.releaseSha256)
    )
      throw new Failure('INVALID_REQUEST');
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.owner(tx, owner);
      const b = await this.device(tx, owner, input.deviceId);
      const requestDigest = hash(
        canonicalReport({
          // Keep persisted installation keys stable across this refactor.
          name: 'iSign Client.ipa',
          source: 'upload',
          deviceId: b.deviceId,
          connectionId: b.connectionId,
          generation: b.generation,
          connectionOwnerId: b.connectionOwnerId,
          grantId: b.grantId,
          grantGeneration: b.grantGeneration,
          provenance: { kind: 'isign-client', sha256: input.releaseSha256 },
        }),
      );
      const previous = (
        await tx.query<{ id: string; upload_id: string; request_digest: string }>(
          'SELECT id,upload_id,request_digest FROM jobs WHERE owner_id=$1 AND idempotency_key=$2',
          [owner, input.key],
        )
      ).rows[0];
      if (previous) {
        if (previous.request_digest !== requestDigest)
          throw new Failure('IDEMPOTENCY_BINDING_MISMATCH', 409);
        return { jobId: previous.id, uploadId: previous.upload_id };
      }
      await this.vacant(tx, owner);
      const uploadId = id(),
        jobId = id();
      await tx.query(
        "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES($1,$2,'iSign Client.ipa',$3,0,$4,'receiving',$5,$6)",
        [uploadId, owner, uploadId + '.ipa', input.releaseSha256, this.now, this.now + 1800000],
      );
      await tx.query(
        `INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_owner_id,connection_generation,access_grant_id,access_grant_generation,state,idempotency_key,created_at,updated_at,display_snapshot,request_digest)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'receiving',$10,$11,$11,$12,$13)`,
        [
          jobId,
          owner,
          uploadId,
          b.deviceId,
          b.connectionId,
          b.connectionOwnerId,
          b.generation,
          b.grantId,
          b.grantGeneration,
          input.key,
          this.now,
          JSON.stringify({
            name: 'iSign Client',
            version: input.version ?? null,
            device: b.deviceName,
          }),
          requestDigest,
        ],
      );
      return { jobId, uploadId };
    });
  }
  async completeSource(owner: string, jobId: string) {
    const rows = await this.db.query<{ device_id: string }>(
      `UPDATE jobs j SET state='queued',updated_at=$3 WHERE id=$1 AND owner_id=$2 AND state='receiving' AND ${eligible} RETURNING device_id`,
      [jobId, owner, this.now],
    );
    if (!rows.rows.length) throw new Failure('SIGNING_INPUT_NOT_READY', 409);
    this.notify(owner, jobId, rows.rows[0].device_id);
  }
  async claim(jobId: string, ownerId: string) {
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await tx.query('SELECT id FROM personal_state WHERE id=1 FOR UPDATE');
      if ((await tx.query('SELECT id FROM jobs WHERE state IN' + working + ' LIMIT 1')).rows.length)
        throw new Failure('RUNNER_BUSY', 409);
      const ready = await tx.query(
        `SELECT id FROM jobs j WHERE id=$1 AND owner_id=$2 AND state='queued' AND attempts<2 AND next_attempt_at<=$3 AND ${eligible} FOR UPDATE OF j`,
        [jobId, ownerId, this.now],
      );
      if (!ready.rows.length) throw new Failure('NOT_CLAIMABLE', 409);
      const lease = token();
      await tx.query(
        "UPDATE jobs SET state='analyzing',reason=NULL,lease_token=$3,lease_expires=$4,attempts=attempts+1,updated_at=$5 WHERE id=$1 AND owner_id=$2",
        [jobId, ownerId, lease, this.now + 60000, this.now],
      );
      return lease;
    });
  }
  async heartbeat(jobId: string, ownerId: string, lease: string) {
    const row = await this.db.query(
      `UPDATE jobs j SET lease_expires=$4 WHERE id=$1 AND owner_id=$2 AND lease_token=$5 AND lease_expires>$3 AND state IN${working} AND ${eligible} RETURNING id`,
      [jobId, ownerId, this.now, this.now + 60000, lease],
    );
    if (!row.rows.length) throw new Failure('LEASE_LOST', 409);
  }
  async deferBusy(lease: Lease) {
    await this.db.query(
      "UPDATE jobs SET state='queued',reason='RUNNER_BUSY',attempts=GREATEST(0,attempts-1),lease_token=NULL,lease_expires=NULL,next_attempt_at=$4,updated_at=$5 WHERE id=$1 AND owner_id=$2 AND lease_token=$3 AND state='analyzing'",
      [lease.jobId, lease.ownerId, lease.leaseToken, this.now + 5000, this.now],
    );
  }
  async finishAttempt(
    lease: Lease,
    outcome: { code?: string; cancelled?: boolean },
  ): Promise<{ state: FinalState }> {
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      const row = (
        await tx.query<{
          state: FinalState;
          lease_token: string | null;
          attempts: number;
          valid: boolean;
        }>(
          `SELECT state,lease_token,attempts,${eligible} AS valid FROM jobs j WHERE id=$1 AND owner_id=$2 FOR UPDATE OF j`,
          [lease.jobId, lease.ownerId, this.now],
        )
      ).rows[0];
      if (!row || row.lease_token !== lease.leaseToken)
        return { state: row?.state === 'ready' ? 'ready' : 'cancelled' };
      const retry =
        !outcome.cancelled &&
        row.valid &&
        row.attempts < 2 &&
        classifyJobFailure(outcome.code ?? 'UNKNOWN') === 'retryable';
      const state = retry ? 'queued' : outcome.cancelled ? 'cancelled' : 'failed';
      await tx.query(
        'UPDATE jobs SET state=$3,reason=$4,lease_token=NULL,lease_expires=NULL,next_attempt_at=$5,finished_at=$6,updated_at=$7 WHERE id=$1 AND owner_id=$2',
        [
          lease.jobId,
          lease.ownerId,
          state,
          outcome.code ?? 'PIPELINE_FAILED',
          retry ? this.now + 5000 : 0,
          retry ? null : this.now,
          this.now,
        ],
      );
      await tx.query('UPDATE executor_tasks SET consumed=true WHERE job_id=$1 AND owner_id=$2', [
        lease.jobId,
        lease.ownerId,
      ]);
      if (!retry)
        await tx.query(
          'UPDATE uploads SET delete_requested_at=$3 WHERE id IN(SELECT upload_id FROM jobs WHERE id=$1 AND owner_id=$2)',
          [lease.jobId, lease.ownerId, this.now],
        );
      return { state };
    });
  }
  async failReceiving(owner: string, job: string, code: string) {
    await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      const row = await tx.query(
        "UPDATE jobs SET state='failed',reason=$3,finished_at=$4,updated_at=$4 WHERE id=$1 AND owner_id=$2 AND state='receiving' RETURNING upload_id",
        [job, owner, code, this.now],
      );
      if (row.rows.length)
        await tx.query(
          'UPDATE uploads SET delete_requested_at=$3 WHERE id IN(SELECT upload_id FROM jobs WHERE id=$1 AND owner_id=$2)',
          [job, owner, this.now],
        );
    });
  }
  /** Only called after acquiring the runtime singleton, before accepting requests. */
  async recoverReceiving() {
    const jobs = (
      await this.db.query<{ id: string; owner_id: string }>(
        "SELECT id,owner_id FROM jobs WHERE state='receiving'",
      )
    ).rows;
    for (const job of jobs)
      await this.failReceiving(job.owner_id, job.id, 'SOURCE_RECEIVE_INTERRUPTED');
  }
  async recoverLeases(
    retireExecutor?: (grant: ExecutorGrant) => Promise<void>,
    retireLaunch?: (nonce: string) => Promise<void>,
  ) {
    const expired = (
      await this.db.query<{ id: string; owner_id: string; lease_token: string }>(
        'SELECT id,owner_id,lease_token FROM jobs WHERE state IN' +
          working +
          ' AND lease_expires<=$1',
        [this.now],
      )
    ).rows;
    for (const job of expired) {
      const tasks = (
        await this.db.query<{ binding: ExecutorGrant }>(
          'SELECT binding FROM executor_tasks WHERE job_id=$1 AND owner_id=$2 AND consumed=false',
          [job.id, job.owner_id],
        )
      ).rows;
      if (tasks.length && !retireExecutor && !retireLaunch) continue;
      try {
        if (retireLaunch) await retireLaunch(job.lease_token);
        else for (const task of tasks) await retireExecutor!(task.binding);
      } catch {
        continue;
      }
      await this.finishAttempt(
        { ownerId: job.owner_id, jobId: job.id, leaseToken: job.lease_token },
        { code: 'RUNNER_INTERRUPTED' },
      );
    }
    const abandoned = (
      await this.db.query<{ id: string; owner_id: string }>(
        "SELECT j.id,j.owner_id FROM jobs j JOIN uploads u ON u.id=j.upload_id AND u.owner_id=j.owner_id WHERE j.state='receiving' AND u.expires_at<=$1",
        [this.now],
      )
    ).rows;
    for (const job of abandoned)
      await this.failReceiving(job.owner_id, job.id, 'SOURCE_RECEIVE_INTERRUPTED');
  }
}
export interface JobLeaseService {
  deferBusy(lease: Lease): Promise<void>;
  claim(jobId: string, ownerId: string): Promise<string>;
  heartbeat(jobId: string, ownerId: string, lease: string): Promise<void>;
  finishAttempt(
    lease: Lease,
    outcome: { code?: string; cancelled?: boolean },
  ): Promise<{ state: FinalState }>;
}
