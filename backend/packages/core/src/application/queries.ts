import type { QueryDatabase } from '../shared/database';
export class RuntimeQueries {
  constructor(
    private db: QueryDatabase,
    private now: () => number,
  ) {}
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
