import type { Database } from '../shared/database';
import { Failure } from '../shared/errors';
import { id } from '../shared/identifiers';
import { invalidateAccess } from './access-lifecycle';
import { lockPrincipalConnections } from './access';

type FreshAuth = {
  fresh(raw: string, csrf: string, origin: string, expected: string): Promise<{ ownerId: string }>;
};
export class ConnectionLifecycle {
  constructor(
    public db: Database,
    private clock: () => number,
    private sessions: FreshAuth,
  ) {}
  get now() {
    return this.clock();
  }
  async disconnect(raw: string, csrf: string, origin: string, expected: string) {
    const { ownerId } = await this.sessions.fresh(raw, csrf, origin, expected);
    await this.disconnectFor(ownerId);
  }
  async disconnectFor(ownerId: string) {
    await this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, ownerId);
      const binding = (
        await tx.query<{
          connection_id: string;
          connection_owner_id: string;
          grant_id: string | null;
        }>('SELECT * FROM user_apple_bindings WHERE user_id=$1 FOR UPDATE', [ownerId])
      ).rows[0];
      if (!binding) throw new Failure('CONNECTION_UNAVAILABLE', 409);
      if (binding.grant_id) {
        await tx.query("UPDATE apple_access_grants SET state='revoked',revoked_at=$2 WHERE id=$1", [
          binding.grant_id,
          this.now,
        ]);
        await invalidateAccess(
          tx,
          { grantId: binding.grant_id },
          'APPLE_SHARE_DISCONNECTED',
          this.now,
        );
        await tx.query('DELETE FROM user_apple_bindings WHERE user_id=$1', [ownerId]);
      } else {
        await invalidateAccess(
          tx,
          { connectionId: binding.connection_id },
          'APPLE_DISCONNECTED',
          this.now,
        );
        await tx.query(
          "UPDATE apple_access_grants SET state='revoked',revoked_at=$2 WHERE connection_id=$1",
          [binding.connection_id, this.now],
        );
        await tx.query('DELETE FROM user_apple_bindings WHERE connection_id=$1', [
          binding.connection_id,
        ]);
        await tx.query(
          "UPDATE connections SET state='disconnected',generation=generation+1,secret_ref=NULL WHERE id=$1",
          [binding.connection_id],
        );
        const removed = await tx.query<{ id: string }>(
          'UPDATE secrets SET deleted_at=$3 WHERE owner_id=$1 AND connection_id=$2 AND deleted_at IS NULL RETURNING id',
          [ownerId, binding.connection_id, this.now],
        );
        for (const secret of removed.rows)
          await tx.query(
            'INSERT INTO secret_deletions(id,owner_id,secret_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(owner_id,secret_id) DO NOTHING',
            [id(), ownerId, secret.id, this.now],
          );
      }
    });
  }
}
