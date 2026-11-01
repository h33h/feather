import { id } from '../../packages/core/src/shared';
import type { JobLifecycle } from '../../packages/core/src/signing/job-lifecycle';

/** Seed an uploaded source for tests of workers, provisioning and publication. */
export async function queuedJobFixture(
  jobs: Pick<JobLifecycle, 'db' | 'now'>,
  owner: string,
  upload: string,
  key: string,
  deviceId?: string,
) {
  const result = await jobs.db.query<{ id: string }>(
    `INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_owner_id,connection_generation,access_grant_id,access_grant_generation,state,idempotency_key,created_at,updated_at,display_snapshot)
     SELECT $1,$2,u.id,d.id,c.id,c.connection_owner_id,c.generation,c.access_grant_id,c.access_grant_generation,'queued',$4,$5,$5,jsonb_build_object('name',u.name)
     FROM uploads u JOIN signing_devices d ON d.owner_id=u.owner_id
     JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=d.owner_id
     WHERE u.id=$3 AND u.owner_id=$2 AND ($6::text IS NULL OR d.id=$6)
     ORDER BY d.selected DESC,d.id LIMIT 1 RETURNING id`,
    [id(), owner, upload, key, jobs.now, deviceId ?? null],
  );
  if (!result.rows[0]) throw new Error('QUEUED_JOB_FIXTURE_REQUIRES_SOURCE_AND_DEVICE');
  return result.rows[0];
}
