import { invalidateNativeSessions } from './native-sessions';
import type { Database, QueryDatabase } from '../shared/database';
import { lockPrincipalConnections } from '../apple/access';
import { invalidateAccess } from '../apple/access-lifecycle';
import { Failure } from '../shared/errors';

type FreshAuth = {
  fresh(raw: string, csrf: string, origin: string, expected: string): Promise<{ ownerId: string }>;
};
export class AccountLifecycle {
  constructor(
    public db: Database,
    private clock: () => number,
    private sessions: FreshAuth,
  ) {}
  get now() {
    return this.clock();
  }
  async deleteAccount(raw: string, csrf: string, origin: string, expected: string) {
    const session = await this.sessions.fresh(raw, csrf, origin, expected);
    await this.removeProfile(session.ownerId);
  }
  async removeProfile(ownerId: string) {
    await this.db.transaction((tx) => removeProfileRows(tx, ownerId, this.now));
  }
}
export async function removeProfileRows(tx: QueryDatabase, ownerId: string, now: number) {
  await lockPrincipalConnections(tx, ownerId);
  const user = (
    await tx.query<{ role: string; blocked_at: number | null }>(
      'SELECT role,blocked_at FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',
      [ownerId],
    )
  ).rows[0];
  if (!user) throw new Failure('USER_UNAVAILABLE', 404);
  if (
    user.role === 'admin' &&
    user.blocked_at === null &&
    !(
      await tx.query(
        "SELECT id FROM users WHERE role='admin' AND blocked_at IS NULL AND deleted_at IS NULL AND id<>$1 LIMIT 1",
        [ownerId],
      )
    ).rows.length
  )
    throw new Failure('LAST_ADMIN_REQUIRED', 409);
  await invalidateAccess(tx, { userId: ownerId }, 'ACCOUNT_DELETED', now);
  await tx.query("UPDATE users SET deleted_at=$2,login_name='deleted_'||id WHERE id=$1", [
    ownerId,
    now,
  ]);
  await tx.query('DELETE FROM sessions WHERE owner_id=$1', [ownerId]);
  await invalidateNativeSessions(tx, ownerId, now);
  await tx.query('DELETE FROM passkeys WHERE owner_id=$1', [ownerId]);
  await tx.query('DELETE FROM passkey_challenges WHERE owner_id=$1', [ownerId]);
  await tx.query('DELETE FROM passkey_invites WHERE owner_id=$1', [ownerId]);
  await tx.query('DELETE FROM device_collection_challenges WHERE owner_id=$1', [ownerId]);
  await tx.query('UPDATE device_collection_checks SET device_id=NULL WHERE owner_id=$1', [ownerId]);
  await tx.query('DELETE FROM collected_devices WHERE owner_id=$1', [ownerId]);
  await tx.query(
    "UPDATE connections SET state='disconnected',generation=generation+1,secret_ref=NULL WHERE owner_id=$1",
    [ownerId],
  );
  await tx.query(
    "UPDATE apple_access_grants SET state='revoked',revoked_at=$2 WHERE connection_owner_id=$1 OR recipient_id=$1",
    [ownerId, now],
  );
  await tx.query('DELETE FROM user_apple_bindings WHERE user_id=$1 OR connection_owner_id=$1', [
    ownerId,
  ]);
  await tx.query(
    'INSERT INTO secret_deletions(id,owner_id,secret_id,created_at) SELECT id,owner_id,id,$2 FROM secrets WHERE owner_id=$1 ON CONFLICT(owner_id,secret_id) DO NOTHING',
    [ownerId, now],
  );
  await tx.query('UPDATE secrets SET deleted_at=$2 WHERE owner_id=$1 AND deleted_at IS NULL', [
    ownerId,
    now,
  ]);
  await tx.query(
    "UPDATE sources SET state='deleted',feed=NULL,canonical_url=NULL WHERE owner_id=$1",
    [ownerId],
  );
  await tx.query('DELETE FROM releases WHERE owner_id=$1', [ownerId]);
  await tx.query('DELETE FROM selections WHERE owner_id=$1', [ownerId]);
  await tx.query('UPDATE jobs SET display_snapshot=NULL WHERE owner_id=$1', [ownerId]);
  await tx.query('DELETE FROM audit WHERE owner_id=$1', [ownerId]);
}
