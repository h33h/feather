import type { QueryDatabase } from '../shared/database';
import { Failure } from '../shared/errors';
import type { ExecutorGrant } from '../shared/runner-contracts';

type Scope = { userId?: string; connectionId?: string; grantId?: string; deviceId?: string };

/** Authority mutations share one short transaction lock on this small single-host service. */
export async function lockAuthority(tx: QueryDatabase) {
  await tx.query('SELECT pg_advisory_xact_lock(736490)');
}

export async function invalidateAccess(
  tx: QueryDatabase,
  scope: Scope,
  reason: string,
  now: number,
): Promise<void> {
  const entries = Object.entries(scope).filter(([, value]) => value !== undefined);
  if (entries.length !== 1) throw new Failure('INVALID_INVALIDATION_SCOPE');
  const [kind, value] = entries[0];
  const predicate = {
    userId: '(owner_id=$1 OR connection_owner_id=$1)',
    connectionId: 'connection_id=$1',
    grantId: 'access_grant_id=$1',
    deviceId: 'device_id=$1',
  }[kind as keyof Scope];
  if (!predicate || typeof value !== 'string' || !value)
    throw new Failure('INVALID_INVALIDATION_SCOPE');
  await lockAuthority(tx);
  const affected = 'SELECT id FROM jobs WHERE ' + predicate;
  await tx.query(
    "UPDATE jobs SET state='cancelled',reason=$2,lease_token=NULL,lease_expires=NULL,finished_at=$3,updated_at=$3 WHERE " +
      predicate +
      " AND state IN('receiving','queued','analyzing','provisioning','signing','verifying')",
    [value, reason, now],
  );
  await tx.query('UPDATE executor_tasks SET consumed=true WHERE job_id IN(' + affected + ')', [
    value,
  ]);
  await tx.query(
    'UPDATE uploads SET delete_requested_at=$2 WHERE id IN(SELECT upload_id FROM jobs WHERE ' +
      predicate +
      ')',
    [value, now],
  );
  await tx.query(
    'UPDATE artifacts SET verified=false,expires_at=LEAST(expires_at,$2) WHERE job_id IN(' +
      affected +
      ')',
    [value, now],
  );
  await tx.query(
    "UPDATE tickets SET state='revoked' WHERE artifact_id IN(SELECT id FROM artifacts WHERE job_id IN(" +
      affected +
      '))',
    [value],
  );
  const registrationPredicate = {
    userId: '(principal_id=$1 OR connection_owner_id=$1)',
    connectionId: 'connection_id=$1',
    grantId: 'access_grant_id=$1',
    deviceId: 'device_id=$1',
  }[kind as keyof Scope];
  await tx.query(
    "UPDATE device_registration_operations SET state='revoked' WHERE " +
      registrationPredicate +
      " AND state IN('submitted','unknown')",
    [value],
  );
}

export async function assertJobAccess(db: QueryDatabase, grant: ExecutorGrant, now: number) {
  const result = await db.query(
    "SELECT j.id FROM signing_jobs j JOIN apple_connections c ON c.id=j.connection_id AND c.owner_id=j.owner_id JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id JOIN uploads u ON u.id=j.upload_id AND u.owner_id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$3 AND j.lease_expires>$4 AND j.state IN('analyzing','provisioning','signing','verifying') AND c.state='ready' AND c.id=$5 AND c.generation=$6 AND j.connection_generation=c.generation AND d.id=$7 AND d.status='ready' AND d.connection_generation=c.generation AND u.digest=$8 AND u.delete_requested_at IS NULL",
    [
      grant.jobId,
      grant.ownerId,
      grant.leaseToken,
      now,
      grant.connectionId,
      grant.connectionGeneration,
      grant.deviceId,
      grant.uploadDigest,
    ],
  );
  if (!result.rows.length || grant.expiresAt <= now) throw new Failure('STALE_EXECUTOR_LEASE', 409);
}
