import type { QueryDatabase } from '../shared/database';

export type AppleBinding = {
  userId: string;
  connectionId: string;
  connectionOwnerId: string;
  connectionGeneration: number;
  grantId: string | null;
  grantGeneration: number | null;
};

export async function resolveBinding(
  db: QueryDatabase,
  userId: string,
): Promise<AppleBinding | null> {
  const result = await db.query<AppleBinding>(
    'SELECT owner_id AS "userId",id AS "connectionId",connection_owner_id AS "connectionOwnerId",generation AS "connectionGeneration",access_grant_id AS "grantId",access_grant_generation AS "grantGeneration" FROM apple_connections WHERE owner_id=$1',
    [userId],
  );
  return result.rows[0] ?? null;
}
