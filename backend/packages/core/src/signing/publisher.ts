import { artifactDeadline, scheduleTerminalCleanup } from '../library/object-lifecycle';
import { assertJobAccess } from '../apple/access-lifecycle';
import { lockAppleAccess, lockPrincipalConnections } from '../apple/access';
import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure, id, token } from '../shared/index';
import type { ExecutorGrant, VerifiedReport } from '../shared/runner-contracts';
import { canonicalReport } from '../shared/canonical-json';
export interface ArtifactStore {
  retentionMs?: number;
  ready?: (key: string) => Promise<void>;
  expiresAt?: (key: string) => Promise<number>;
  published?: (tx: QueryDatabase, owner: string, job: string) => Promise<void>;
  confirmStored?: (tx: QueryDatabase, key: string, owner: string, size: number) => Promise<void>;
  put(
    key: string,
    body: AsyncIterable<Uint8Array>,
    ownerId?: string,
  ): Promise<{
    digest: string;
    size: number;
    version?: string;
  }>;
  delete(key: string, ownerId?: string): Promise<void>;
}
export interface ExecutorAttestor {
  verify(report: VerifiedReport, attestation: string): Promise<boolean>;
}
export class HmacExecutorAttestor implements ExecutorAttestor {
  constructor(private key: Buffer) {
    if (key.length < 32) throw new Failure('INVALID_EXECUTOR_ATTESTATION_KEY', 503);
  }
  async verify(report: VerifiedReport, attestation: string) {
    if (!/^[a-f0-9]{64}$/.test(attestation)) return false;
    const expected = createHmac('sha256', this.key).update(canonicalReport(report)).digest();
    return timingSafeEqual(expected, Buffer.from(attestation, 'hex'));
  }
}
const active =
  "SELECT j.id,j.owner_id,j.upload_id,j.device_id,u.digest,c.id AS connection_id,c.generation,c.connection_owner_id,c.access_grant_id,c.access_grant_generation FROM signing_jobs j JOIN uploads u ON u.id=j.upload_id AND u.owner_id=j.owner_id JOIN users o ON o.id=j.owner_id JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$3 AND j.lease_expires>$4 AND j.state IN('analyzing','provisioning','signing','verifying') AND o.deleted_at IS NULL AND u.expires_at>$4 AND d.status='ready' AND c.state='ready'";
type Eligible = {
  id: string;
  owner_id: string;
  device_id: string;
  digest: string;
  connection_id: string;
  generation: number;
  connection_owner_id: string;
  access_grant_id: string | null;
  access_grant_generation: number | null;
};
export class Publisher {
  constructor(
    private db: Database,
    private store: ArtifactStore,
    private attestor: ExecutorAttestor,
    private now: () => number,
  ) {}
  async grant(
    ownerId: string,
    jobId: string,
    leaseToken: string,
    isolationInstanceId: string,
    planDigest: string | undefined,
    maxExpiresAt: number,
  ): Promise<ExecutorGrant> {
    if (!Number.isSafeInteger(maxExpiresAt) || maxExpiresAt <= this.now())
      throw new Failure('EXECUTOR_INSTANCE_EXPIRED', 409);
    if (planDigest !== undefined && !/^[a-f0-9]{64}$/.test(planDigest))
      throw new Failure('PLAN_DIGEST_INVALID');
    if (!/^[A-Za-z0-9_.:-]{1,128}$/.test(isolationInstanceId))
      throw new Failure('ISOLATION_REQUIRED');
    return this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, ownerId);
      await tx.query(
        'SELECT c.id FROM connections c JOIN jobs j ON j.connection_id=c.id WHERE j.id=$1 AND j.owner_id=$2 FOR UPDATE OF c',
        [jobId, ownerId],
      );
      const result = await tx.query<Eligible>(active + ' FOR UPDATE OF o', [
        jobId,
        ownerId,
        leaseToken,
        this.now(),
      ]);
      const row = result.rows[0];
      if (!row) throw new Failure('STALE_EXECUTOR_LEASE', 409);
      const grant: ExecutorGrant = {
        ownerId,
        connectionOwnerId: row.connection_owner_id,
        ...(row.connection_owner_id !== ownerId
          ? {
              accessGrantId: row.access_grant_id!,
              accessGrantGeneration: row.access_grant_generation!,
            }
          : {}),
        jobId,
        leaseToken,
        connectionId: row.connection_id,
        connectionGeneration: row.generation,
        deviceId: row.device_id,
        uploadDigest: row.digest,
        taskNonce: token(),
        isolationInstanceId,
        expiresAt: Math.min(this.now() + 15 * 60000, maxExpiresAt),
        ...(planDigest ? { planDigest } : {}),
      };
      if (grant.expiresAt <= this.now()) throw new Failure('EXECUTOR_INSTANCE_EXPIRED', 409);
      await tx.query(
        'INSERT INTO executor_tasks(nonce,owner_id,job_id,binding,expires_at) VALUES($1,$2,$3,$4,$5)',
        [grant.taskNonce, ownerId, jobId, JSON.stringify(grant), grant.expiresAt],
      );
      return grant;
    });
  }
  async publish(report: VerifiedReport, attestation: string, body: AsyncIterable<Uint8Array>) {
    if (!(await this.attestor.verify(report, attestation)))
      throw new Failure('EXECUTOR_ATTESTATION_INVALID', 403);
    if (
      !/^[a-f0-9]{64}$/.test(report.artifactDigest) ||
      !report.bundleId ||
      report.bundleId.length > 255 ||
      !report.version ||
      report.version.length > 80 ||
      !report.title ||
      report.title.length > 200 ||
      Object.keys(report.checks).length !== 7 ||
      ['archive', 'components', 'signatures', 'profiles', 'device', 'entitlements', 'mapping'].some(
        (k) => report.checks[k as keyof VerifiedReport['checks']] !== true,
      )
    )
      throw new Failure('ARTIFACT_VERIFICATION_FAILED');
    const artifactId = id(),
      key = artifactId + '.ipa';
    let committed = false;
    try {
      const stored = await this.store.put(key, body, report.ownerId);
      if (stored.digest !== report.artifactDigest) throw new Failure('ARTIFACT_DIGEST_MISMATCH');
      const result = await this.db.transaction(async (tx) => {
        await lockPrincipalConnections(tx, report.ownerId);
        await tx.query('SELECT id FROM connections WHERE id=$1 FOR UPDATE', [report.connectionId]);
        await this.store.confirmStored?.(tx, key, report.ownerId, stored.size);
        const task = await tx.query<{
          binding: ExecutorGrant;
        }>(
          'SELECT binding FROM executor_tasks WHERE nonce=$1 AND owner_id=$2 AND job_id=$3 AND consumed=false AND expires_at>$4 FOR UPDATE',
          [report.taskNonce, report.ownerId, report.jobId, this.now()],
        );
        if (!task.rows[0]) throw new Failure('STALE_EXECUTOR_GRANT', 409);
        if (
          !task.rows[0].binding.planDigest ||
          report.planDigest !== task.rows[0].binding.planDigest
        )
          throw new Failure('PLAN_DIGEST_MISMATCH', 409);
        for (const key of Object.keys(task.rows[0].binding) as (keyof ExecutorGrant)[])
          if (task.rows[0].binding[key] !== report[key])
            throw new Failure('EXECUTOR_BINDING_MISMATCH', 409);
        await lockAppleAccess(tx, { ...report, generation: report.connectionGeneration });
        const r = await tx.query<Eligible>(active + ' FOR UPDATE OF o', [
          report.jobId,
          report.ownerId,
          report.leaseToken,
          this.now(),
        ]);
        const row = r.rows[0];
        if (
          !row ||
          row.connection_id !== report.connectionId ||
          row.generation !== report.connectionGeneration ||
          row.device_id !== report.deviceId ||
          row.digest !== report.uploadDigest
        )
          throw new Failure('STALE_EXECUTOR_LEASE', 409);
        const validUntil = Math.min(report.certificateExpiresAt, report.profileExpiresAt);
        if (
          ![report.certificateExpiresAt, report.profileExpiresAt].every(
            (v) => Number.isSafeInteger(v) && v > this.now(),
          ) ||
          !Number.isSafeInteger(validUntil) ||
          validUntil <= this.now()
        )
          throw new Failure('SIGNING_MATERIAL_EXPIRED');
        await assertJobAccess(tx, report, this.now());
        const readyAt = this.now();
        await tx.query(
          'INSERT INTO artifacts(id,owner_id,job_id,connection_id,device_id,object_key,digest,metadata,valid_until,created_at,ready_at,expires_at,verified,connection_owner_id,access_grant_id,access_grant_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10,$11,true,$12,$13,$14)',
          [
            artifactId,
            report.ownerId,
            report.jobId,
            report.connectionId,
            report.deviceId,
            key,
            report.artifactDigest,
            JSON.stringify({
              bundleId: report.bundleId,
              version: report.version,
              title: report.title,
              generation: report.connectionGeneration,
              size: stored.size,
              isolationInstanceId: report.isolationInstanceId,
            }),
            validUntil,
            readyAt,
            artifactDeadline(readyAt, report.certificateExpiresAt, report.profileExpiresAt),
            row.connection_owner_id,
            row.access_grant_id,
            row.access_grant_generation,
          ],
        );
        await tx.query('UPDATE executor_tasks SET consumed=true WHERE nonce=$1', [
          report.taskNonce,
        ]);
        await tx.query(
          "UPDATE jobs SET state='ready',reason=NULL,lease_token=NULL,lease_expires=NULL,updated_at=$2,finished_at=$2,display_snapshot=COALESCE(display_snapshot,'{}'::jsonb)||$3::jsonb WHERE id=$1",
          [report.jobId, readyAt, JSON.stringify({ name: report.title, version: report.version })],
        );
        await scheduleTerminalCleanup(tx, report.jobId, readyAt);
        await this.store.published?.(tx, report.ownerId, report.jobId);
        return { id: artifactId };
      });
      committed = true;
      await this.store.ready?.(key);
      return result;
    } finally {
      if (!committed) await this.store.delete(key, report.ownerId);
    }
  }
}
