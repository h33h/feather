import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { ProductionDatabase } from '../../packages/core/src/infrastructure/postgres';

/** Explicit loopback test database only; never load the application's DATABASE_URL. */
export async function postgresFixture() {
  const rootUrl = new URL(process.env.ISIGN_TEST_DATABASE_URL ?? '');
  if (
    !['postgres:', 'postgresql:'].includes(rootUrl.protocol) ||
    !['127.0.0.1', 'localhost', '[::1]'].includes(rootUrl.hostname) ||
    rootUrl.pathname !== '/isign_test'
  )
    throw new Error('ISOLATED_POSTGRES_TEST_DATABASE_REQUIRED');
  const name = 'isign_test_' + randomUUID().replaceAll('-', '');
  const admin = new Pool({ connectionString: rootUrl.href, max: 1 });
  await admin.query('CREATE DATABASE "' + name + '"');
  const url = new URL(rootUrl);
  url.pathname = '/' + name;
  const pool = new Pool({ connectionString: url.href, max: 5 });
  const disconnects = new Set<Promise<void>>();
  pool.on('connect', (client) => {
    const disconnected = new Promise<void>((resolve) => client.once('end', resolve));
    disconnects.add(disconnected);
    void disconnected.then(() => disconnects.delete(disconnected));
  });
  const db = new ProductionDatabase({
    query: async <T>(sql: string, params?: unknown[]) => ({
      rows: (await pool.query(sql, params)).rows as T[],
    }),
    connect: async () => {
      const client = await pool.connect();
      return {
        query: async <T>(sql: string, params?: unknown[]) => ({
          rows: (await client.query(sql, params)).rows as T[],
        }),
        release: (error?: Error) => client.release(error),
      };
    },
    end: () => pool.end(),
  });
  return {
    db,
    url: url.href,
    async close() {
      await db.close();
      // pg-pool resolves end() after removing idle clients from its registry,
      // before their sockets finish closing. FORCE must not race those clients.
      await Promise.all(disconnects);
      try {
        await admin.query('DROP DATABASE "' + name + '" WITH (FORCE)');
      } finally {
        await admin.end();
      }
    },
  };
}
