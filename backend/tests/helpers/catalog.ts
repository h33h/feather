import type { QueryDatabase } from '../../packages/core/src/shared/database';
import type { Release } from '../../packages/core/src/catalog/gbox';

export async function storedSources(db: QueryDatabase, owner: string) {
  return (
    await db.query<{
      id: string;
      state: string;
      last_error: string | null;
      refresh_failures: number;
      next_refresh_at: number;
    }>('SELECT * FROM sources WHERE owner_id=$1 ORDER BY kind,id', [owner])
  ).rows;
}

export async function storedReleases(db: QueryDatabase, owner: string, source: string) {
  return (
    await db.query<{ id: string; source_id: string; snapshot: string; metadata: Release }>(
      'SELECT * FROM releases WHERE source_id=$1 AND owner_id=$2 ORDER BY id',
      [source, owner],
    )
  ).rows;
}
