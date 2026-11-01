import { PGlite } from '@electric-sql/pglite';
import { initializeDatabase } from '../../packages/core/src/infrastructure/database-init';
import type { Database } from '../../packages/core/src/shared/database';

export async function createDatabase() {
  const db = new PGlite();
  try {
    await initializeDatabase(db as unknown as Database);
    return db;
  } catch (error) {
    await db.close();
    throw error;
  }
}
