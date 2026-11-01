import type { QueryDatabase } from '../shared/database';
export class RuntimeQueries {
  constructor(
    private db: QueryDatabase,
    private now: () => number,
  ) {}
  async library(owner: string) {
    const jobs = (
      await this.db.query(
        "SELECT id,upload_id,device_id,state,reason,created_at,updated_at,finished_at,display_snapshot,warnings,attempts FROM jobs WHERE owner_id=$1 AND (state IN('receiving','queued','analyzing','provisioning','signing','verifying') OR (finished_at>$2 AND state IN('failed','cancelled')) OR id IN(SELECT job_id FROM signing_artifacts WHERE owner_id=$1 AND verified AND expires_at>$3 AND valid_until>$3)) ORDER BY created_at DESC,id DESC LIMIT 100",
        [owner, this.now() - 600000, this.now()],
      )
    ).rows;
    const artifacts = (
      await this.db.query(
        "SELECT a.id,a.job_id,a.created_at,a.expires_at,a.valid_until,a.verified,true AS eligible FROM signing_artifacts a JOIN apple_connections c ON c.id=a.connection_id AND c.owner_id=a.owner_id JOIN signing_devices d ON d.id=a.device_id AND d.owner_id=a.owner_id JOIN jobs j ON j.id=a.job_id AND j.owner_id=a.owner_id WHERE a.owner_id=$1 AND a.verified AND a.expires_at>$2 AND a.valid_until>$2 AND j.state='ready' AND c.state='ready' AND c.generation=(a.metadata->>'generation')::integer AND d.status='ready' AND d.connection_generation=c.generation ORDER BY a.created_at DESC",
        [owner, this.now()],
      )
    ).rows;
    return { jobs, artifacts };
  }
  async apple(owner: string) {
    const connections = (
      await this.db.query(
        `SELECT c.id,c.team_id,c.state,c.generation,c.last_error,c.connection_owner_id<>c.owner_id AS shared,CASE WHEN c.key_id IS NULL THEN NULL ELSE '••••••'||right(c.key_id,4) END AS key_id,EXISTS(SELECT 1 FROM bootstrap_operations b JOIN secrets s ON s.id=b.identity->>'secretRef' AND s.owner_id=b.owner_id WHERE b.owner_id=c.connection_owner_id AND b.connection_id=c.id AND b.generation=c.generation AND b.certificate_state='committed' AND s.deleted_at IS NULL AND (b.certificate->>'expiresAt')::bigint>$2) AS "identityReady" FROM apple_connections c WHERE c.owner_id=$1`,
        [owner, this.now()],
      )
    ).rows;
    const connection = connections[0] ?? null;
    return { connection, uploadAllowed: connection?.state === 'ready' };
  }
  async devices(owner: string) {
    return (
      await this.db.query(
        "SELECT d.id,d.name,CASE WHEN c.id IS NULL THEN 'connection_changed' ELSE d.status END AS status,d.os_version,d.os_version_source,d.selected,c.team_id FROM devices d LEFT JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=d.owner_id AND c.generation=d.connection_generation AND c.access_grant_id IS NOT DISTINCT FROM d.access_grant_id AND c.access_grant_generation IS NOT DISTINCT FROM d.access_grant_generation WHERE d.owner_id=$1 AND d.status<>'locally_removed' ORDER BY d.name,d.id",
        [owner],
      )
    ).rows;
  }
}
