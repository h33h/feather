import type { QueryDatabase } from '../shared/database';
import { Failure } from '../shared/index';
/** Apple connection admission is separate from certificate/device signing readiness. */
export async function hasUploadAccess(db: QueryDatabase, ownerId: string): Promise<boolean> {
  const result = await db.query(
    "SELECT id FROM apple_connections WHERE owner_id=$1 AND state='ready' AND provider='asc' LIMIT 1",
    [ownerId],
  );
  return result.rows.length > 0;
}
/** Check before consuming an upload stream, reserving storage, or importing an IPA. */
export async function assertUploadAccess(db: QueryDatabase, ownerId: string): Promise<void> {
  if (!(await hasUploadAccess(db, ownerId))) throw new Failure('APPLE_ACCESS_REQUIRED', 403);
}
