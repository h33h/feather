import { invalidateNativeSessions } from './native-sessions';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure, id } from '../shared/index';
import { lockAuthority, invalidateAccess } from '../apple/access-lifecycle';
import { issueInvitation, resetCredentials, type PersonalAuth } from './passkeys';
import { removeProfileRows } from './account-lifecycle';
export type AdminUser = {
  id: string;
  loginName: string;
  role: 'user' | 'admin';
  status: 'invited' | 'active' | 'blocked';
  inviteExpiresAt: number | null;
};
export async function requireAdmin(db: QueryDatabase, session: { ownerId: string }, _now: number) {
  if (
    !(
      await db.query(
        "SELECT id FROM users WHERE id=$1 AND role='admin' AND blocked_at IS NULL AND deleted_at IS NULL",
        [session.ownerId],
      )
    ).rows.length
  )
    throw new Failure('ADMIN_REQUIRED', 403);
}
export class AdminUsers {
  constructor(
    private db: Database,
    _auth: PersonalAuth,
    private now: () => number,
  ) {}
  private async mutate<T>(actor: string, work: (tx: QueryDatabase) => Promise<T>) {
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await requireAdmin(tx, { ownerId: actor }, this.now());
      return work(tx);
    });
  }
  async list(actor: string) {
    await requireAdmin(this.db, { ownerId: actor }, this.now());
    return (
      await this.db.query<AdminUser>(
        `SELECT u.id,u.login_name AS "loginName",u.role,CASE WHEN u.blocked_at IS NOT NULL THEN 'blocked' WHEN EXISTS(SELECT 1 FROM passkeys WHERE owner_id=u.id) THEN 'active' ELSE 'invited' END AS status,(SELECT expires_at FROM passkey_invites WHERE owner_id=u.id AND consumed_at IS NULL LIMIT 1) AS "inviteExpiresAt" FROM users u WHERE u.deleted_at IS NULL ORDER BY u.created_at,u.id`,
      )
    ).rows.map((row) => ({
      ...row,
      inviteExpiresAt: row.inviteExpiresAt === null ? null : Number(row.inviteExpiresAt),
    }));
  }
  async invite(actor: string, name: string) {
    if (!/^[a-zA-Z0-9_-]{1,40}$/.test(name)) throw new Failure('LOGIN_NAME_INVALID');
    return this.mutate(actor, async (tx) => {
      const userId = id();
      await tx.query('INSERT INTO users(id,login_name,created_at) VALUES($1,$2,$3)', [
        userId,
        name,
        this.now(),
      ]);
      return { userId, ...(await issueInvitation(tx, userId, this.now())) };
    });
  }
  async reinvite(actor: string, userId: string) {
    return this.mutate(actor, async (tx) => {
      if (
        !(
          await tx.query(
            'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
            [userId],
          )
        ).rows.length
      )
        throw new Failure('USER_UNAVAILABLE', 404);
      await resetCredentials(tx, userId, this.now());
      return issueInvitation(tx, userId, this.now());
    });
  }
  async setBlocked(actor: string, userId: string, blocked: boolean) {
    return this.mutate(actor, async (tx) => {
      const target = (
        await tx.query<{ role: string; blocked_at: number | null }>(
          'SELECT role,blocked_at FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',
          [userId],
        )
      ).rows[0];
      if (!target) throw new Failure('USER_UNAVAILABLE', 404);
      if (
        blocked &&
        target.role === 'admin' &&
        target.blocked_at === null &&
        !(
          await tx.query(
            "SELECT id FROM users WHERE id<>$1 AND role='admin' AND blocked_at IS NULL AND deleted_at IS NULL LIMIT 1",
            [userId],
          )
        ).rows.length
      )
        throw new Failure('LAST_ADMIN_REQUIRED', 409);
      await tx.query('UPDATE users SET blocked_at=$2 WHERE id=$1', [
        userId,
        blocked ? this.now() : null,
      ]);
      if (blocked) {
        await invalidateAccess(tx, { userId }, 'ACCOUNT_BLOCKED', this.now());
        await tx.query('UPDATE bootstrap_operations SET expires_at=0 WHERE owner_id=$1', [userId]);
        await tx.query('DELETE FROM sessions WHERE owner_id=$1', [userId]);
        await invalidateNativeSessions(tx, userId, this.now());
      }
    });
  }
  async remove(actor: string, userId: string) {
    return this.mutate(actor, (tx) => removeProfileRows(tx, userId, this.now()));
  }
}
