import type { QueryDatabase } from '../shared/database';
/** Called after the collection scenario locks the principal. No access-token binding. */
export async function nativeCollectionSession(
  tx: QueryDatabase,
  owner: string,
  sessionId: string,
  now: number,
): Promise<boolean> {
  return !!(
    await tx.query(
      'SELECT id FROM native_sessions WHERE id=$1 AND owner_id=$2 AND revoked_at IS NULL AND refresh_expires_at>$3 FOR UPDATE',
      [sessionId, owner, now],
    )
  ).rows.length;
}
