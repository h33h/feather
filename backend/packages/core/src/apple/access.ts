import { invalidateAccess, lockAuthority } from './access-lifecycle';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure, id } from '../shared/index';
export type AppleAccess = {
  ownerId: string;
  connectionId: string;
  connectionOwnerId: string;
  generation: number;
  accessGrantId?: string | null;
  accessGrantGeneration?: number | null;
};
export type ResolvedAppleAccess = AppleAccess & {
  connectionOwnerId: string;
  accessGrantId: string | null;
  accessGrantGeneration: number | null;
  teamId: string;
};
/** Public IDs locate a recipient; only authenticated principals authorize work. */
export async function resolveAppleAccess(
  db: QueryDatabase,
  ownerId: string,
  connectionId: string,
  generation: number,
): Promise<ResolvedAppleAccess> {
  const result = await db.query<{
    connection_owner_id: string;
    access_grant_id: string | null;
    access_grant_generation: number | null;
    team_id: string;
  }>(
    "SELECT connection_owner_id,access_grant_id,access_grant_generation,team_id FROM apple_connections WHERE id=$1 AND owner_id=$2 AND generation=$3 AND state='ready' AND provider='asc'",
    [connectionId, ownerId, generation],
  );
  const row = result.rows[0];
  if (!row) throw new Failure('APPLE_ACCESS_UNAVAILABLE', 403);
  return {
    ownerId,
    connectionId,
    generation,
    connectionOwnerId: row.connection_owner_id,
    accessGrantId: row.access_grant_id,
    accessGrantGeneration: row.access_grant_generation,
    teamId: row.team_id,
  };
}
export async function assertAppleAccess(db: QueryDatabase, b: AppleAccess) {
  const actual = await resolveAppleAccess(db, b.ownerId, b.connectionId, b.generation);
  if (
    b.connectionOwnerId !== actual.connectionOwnerId ||
    (b.accessGrantId ?? null) !== actual.accessGrantId ||
    (b.accessGrantGeneration ?? null) !== actual.accessGrantGeneration
  )
    throw new Failure('APPLE_ACCESS_CHANGED', 403);
  return actual;
}
export async function lockAppleAccess(tx: QueryDatabase, b: AppleAccess) {
  await tx.query('SELECT id FROM connections WHERE id=$1 FOR UPDATE', [b.connectionId]);
  return assertAppleAccess(tx, b);
}
export class AppleSharing {
  constructor(
    private db: Database,
    private now: () => number,
  ) {}
  async list(principal: string) {
    const result = await this.db.query<{
      id: string;
      generation: number;
      state: string;
      connectionId: string;
      teamId: string;
      direction: string;
      profileId: string;
    }>(
      `SELECT g.id,g.generation,CASE WHEN g.connection_generation<>c.generation OR c.state<>'ready' THEN 'stale' ELSE g.state END AS state,
      c.id AS "connectionId",c.team_id AS "teamId",
      CASE WHEN g.connection_owner_id=$1 THEN 'outgoing' ELSE 'incoming' END AS direction,
      CASE WHEN g.connection_owner_id=$1 THEN r.public_profile_id ELSE o.public_profile_id END AS "profileId"
      FROM apple_access_grants g JOIN connections c ON c.id=g.connection_id AND c.owner_id=g.connection_owner_id
      JOIN users o ON o.id=c.owner_id JOIN users r ON r.id=g.recipient_id
      WHERE (g.connection_owner_id=$1 OR g.recipient_id=$1) AND o.deleted_at IS NULL AND r.deleted_at IS NULL
      ORDER BY g.created_at DESC,g.id`,
      [principal],
    );
    return result.rows;
  }
  async share(owner: string, profileId: string) {
    if (!/^profile_[a-f0-9]{32}$/.test(profileId)) throw new Failure('PROFILE_NOT_FOUND', 404);
    return this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, owner);
      const connection = (
        await tx.query<{ id: string; generation: number }>(
          "SELECT c.id,c.generation FROM connections c JOIN user_apple_bindings b ON b.user_id=c.owner_id AND b.connection_id=c.id AND b.grant_id IS NULL JOIN users u ON u.id=c.owner_id WHERE c.owner_id=$1 AND c.state='ready' AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL FOR UPDATE OF c,u",
          [owner],
        )
      ).rows[0];
      if (!connection) throw new Failure('CONNECTION_UNAVAILABLE', 409);
      const recipient = (
        await tx.query<{ id: string }>(
          'SELECT id FROM users WHERE public_profile_id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
          [profileId],
        )
      ).rows[0];
      if (!recipient || recipient.id === owner) throw new Failure('PROFILE_NOT_FOUND', 404);
      const occupied = await tx.query(
        'SELECT user_id FROM user_apple_bindings WHERE user_id=$1 FOR UPDATE',
        [recipient.id],
      );
      if (occupied.rows.length) throw new Failure('APPLE_CONNECTION_EXISTS', 409);
      const grant = (
        await tx.query<{ id: string; generation: number }>(
          `INSERT INTO apple_access_grants(id,connection_id,connection_owner_id,recipient_id,connection_generation,state,created_at)
        VALUES($1,$2,$3,$4,$5,'accepted',$6)
        ON CONFLICT(connection_id,recipient_id) DO UPDATE SET state='accepted',generation=apple_access_grants.generation+1,connection_generation=EXCLUDED.connection_generation,revoked_at=NULL,created_at=EXCLUDED.created_at
        RETURNING id,generation`,
          [id(), connection.id, owner, recipient.id, connection.generation, this.now()],
        )
      ).rows[0];
      await tx.query(
        'INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id,grant_id) VALUES($1,$2,$3,$4)',
        [recipient.id, connection.id, owner, grant.id],
      );
      await tx.query(
        "INSERT INTO audit(id,owner_id,event,metadata,created_at) VALUES($1,$2,'apple_share_granted',$3,$4)",
        [id(), owner, JSON.stringify({ grantId: grant.id, recipientId: recipient.id }), this.now()],
      );
      return { grantId: grant.id };
    });
  }
  async revoke(owner: string, grantId: string) {
    return this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, owner);
      const grant = (
        await tx.query<{ recipient_id: string }>(
          'SELECT recipient_id FROM apple_access_grants WHERE id=$1 AND connection_owner_id=$2 FOR UPDATE',
          [grantId, owner],
        )
      ).rows[0];
      if (!grant) throw new Failure('SHARE_NOT_FOUND', 404);
      await tx.query("UPDATE apple_access_grants SET state='revoked',revoked_at=$2 WHERE id=$1", [
        grantId,
        this.now(),
      ]);
      await tx.query('DELETE FROM user_apple_bindings WHERE user_id=$1 AND grant_id=$2', [
        grant.recipient_id,
        grantId,
      ]);
      await invalidateAccess(tx, { grantId }, 'APPLE_SHARE_REVOKED', this.now());
      return { ok: true };
    });
  }
}

/** All authority writers take this lock before any principal/connection/job locks. */
export async function lockPrincipalConnections(tx: QueryDatabase, owner: string) {
  await lockAuthority(tx);
  await tx.query(
    'SELECT c.id FROM connections c WHERE c.owner_id=$1 OR EXISTS(SELECT 1 FROM user_apple_bindings b WHERE b.connection_id=c.id AND b.user_id=$1) ORDER BY c.id FOR UPDATE OF c',
    [owner],
  );
}
