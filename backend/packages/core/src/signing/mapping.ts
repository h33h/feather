import type { Database } from '../shared/database';
import { Failure, hash, id } from '../shared/index';
import { lockAuthority } from '../apple/access-lifecycle';
export class MappingService {
  constructor(private db: Database) {}
  async choose(owner: string, connectionId: string, originalId: string, canPreserve: boolean) {
    if (!/^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$/.test(originalId))
      throw new Failure('INVALID_BUNDLE_ID');
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      const connection = (
        await tx.query<{
          team_id: string;
          generation: number;
          connection_owner_id: string;
          access_grant_id: string | null;
          access_grant_generation: number | null;
        }>(
          "SELECT team_id,generation,connection_owner_id,access_grant_id,access_grant_generation FROM apple_connections WHERE id=$1 AND owner_id=$2 AND state='ready'",
          [connectionId, owner],
        )
      ).rows[0];
      if (!connection) throw new Failure('CONNECTION_UNAVAILABLE', 409);
      await tx.query(
        'DELETE FROM mappings WHERE owner_id=$1 AND connection_id=$2 AND (connection_generation<>$3 OR connection_owner_id IS DISTINCT FROM $4 OR access_grant_id IS DISTINCT FROM $5 OR access_grant_generation IS DISTINCT FROM $6)',
        [
          owner,
          connectionId,
          connection.generation,
          connection.connection_owner_id,
          connection.access_grant_id,
          connection.access_grant_generation,
        ],
      );
      const previous = (
        await tx.query<{ id: string; original_id: string; target_id: string }>(
          'SELECT id,original_id,target_id FROM mappings WHERE owner_id=$1 AND connection_id=$2 AND original_id=$3',
          [owner, connectionId, originalId],
        )
      ).rows[0];
      if (previous) return previous;
      const mappingId = id(),
        target = canPreserve
          ? originalId
          : 'com.isignservice.t' +
            hash(connection.team_id).slice(0, 12) +
            '.a' +
            hash(originalId).slice(0, 16);
      await tx.query(
        'INSERT INTO mappings(id,owner_id,connection_id,original_id,target_id,connection_owner_id,access_grant_id,access_grant_generation,connection_generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [
          mappingId,
          owner,
          connectionId,
          originalId,
          target,
          connection.connection_owner_id,
          connection.access_grant_id,
          connection.access_grant_generation,
          connection.generation,
        ],
      );
      return { id: mappingId, original_id: originalId, target_id: target };
    });
  }
  async extension(owner: string, mappingId: string, suffix: string) {
    if (!/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/.test(suffix))
      throw new Failure('INVALID_EXTENSION_ID');
    const row = (
      await this.db.query<{ target_id: string }>(
        'SELECT target_id FROM mappings WHERE id=$1 AND owner_id=$2',
        [mappingId, owner],
      )
    ).rows[0];
    if (!row) throw new Failure('NOT_FOUND', 404);
    return row.target_id + '.' + suffix;
  }
}
