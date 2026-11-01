import { assertInitializedDatabase } from '../infrastructure/database-init';
import { AdminUsers } from '../auth/admin';
import { Pool, types } from 'pg';
import { PersonalAuth } from '../auth/passkeys';
import { PersonalObjects, PersonalStorage, PersonalArtifacts } from '../library/personal-storage';
import { Service } from '../application/service';
import { ProductionDatabase, type SqlPool } from '../infrastructure/postgres';
import { createPostgresPool, safeBigint } from '../infrastructure/postgres-pool';
import { postgresQuery } from '../infrastructure/postgres-query';
import {
  loadProviderConfig,
  providerDiagnostics,
  ProviderError,
  type PersonalConfig,
} from '../infrastructure/config';
import { LocalEnvelopeKms } from '../infrastructure/local-kms';
import { Vault } from '../apple/vault';
import { Tickets } from '../library/tickets';
import { CatalogRegistry } from '../catalog/registry';
import { SecretDeletionWorker } from '../apple/secret-deletion';
export async function createPersonalRuntimeKernel(options: {
  env: Record<string, string | undefined>;
  pool?: SqlPool;
  now?: () => number;
}) {
  const config = loadProviderConfig(options.env);
  if (config.mode !== 'personal') throw new ProviderError('PERSONAL_RUNTIME_REQUIRED');
  const now = options.now ?? Date.now;
  const pool = options.pool ?? createPersonalPool(config, options.env);
  const singleton = await pool.connect();
  const held = await singleton.query<{
    held: boolean;
  }>('SELECT pg_try_advisory_lock(736492) AS held');
  if (!held.rows[0]?.held) {
    singleton.release();
    await pool.end?.();
    throw new ProviderError('PERSONAL_SINGLE_INSTANCE_REQUIRED');
  }
  const instanceGuard = setInterval(() => {
    void singleton.query('SELECT 1').catch(() => {
      process.exitCode = 1;
      process.kill(process.pid, 'SIGTERM');
    });
  }, 10000);
  instanceGuard.unref();
  const db = new ProductionDatabase(pool);
  const originalClose = db.close.bind(db);
  let closing: Promise<void> | undefined;
  db.close = () =>
    (closing ??= (async () => {
      clearInterval(instanceGuard);
      singleton.release();
      await originalClose();
    })());
  try {
    await assertInitializedDatabase(db);
    const kms = new LocalEnvelopeKms({ keyFile: config.keyFile });
    await kms.assertReady();
    const objects = new PersonalObjects(db, config.dataDirectory, now);
    await objects.recover();
    const storage = new PersonalStorage(objects),
      artifacts = new PersonalArtifacts(objects);
    await storage.cleanup();
    await artifacts.cleanup();
    const service = new Service(db, { now }),
      auth = new PersonalAuth(db, config.origin, now),
      vault = new Vault(db, kms, now);
    await service.jobs.recoverReceiving();
    await storage.cleanup();
    const catalogs = new CatalogRegistry(db, now);
    await catalogs.ensureBuiltIns();
    return {
      config,
      db,
      kms,
      storage,
      artifacts,
      service,
      auth,
      admin: new AdminUsers(db, auth, now),
      vault,
      tickets: new Tickets(db, now),
      catalogs,
      secretDeletionWorker: new SecretDeletionWorker(db, vault, now),
      diagnostics: providerDiagnostics(config),
    };
  } catch (error) {
    await db.close();
    throw error;
  }
}
export function createPersonalPool(
  config: PersonalConfig,
  env: Record<string, string | undefined>,
): SqlPool {
  let pool: SqlPool;
  {
    if (config.databaseTransport === 'tls')
      pool = createPostgresPool(config.databaseUrl, { ca: env.ISIGN_DB_CA_PEM, maxConnections: 5 });
    else {
      const pg = new Pool({
        connectionString: config.databaseUrl.reveal(),
        ssl: false,
        max: 5,
        connectionTimeoutMillis: 5000,
        idleTimeoutMillis: 10000,
        statement_timeout: 30000,
        query_timeout: 31000,
        idle_in_transaction_session_timeout: 10000,
        application_name: 'isign-personal',
        types: {
          getTypeParser: (oid, format) =>
            oid === 20 && format !== 'binary' ? safeBigint : types.getTypeParser(oid, format),
        },
      });
      pg.on('error', () => {});
      pool = {
        query: async <T>(sql: string, params?: unknown[]) => ({
          rows: (await pg.query(postgresQuery(sql, params))).rows as T[],
        }),
        connect: async () => {
          const c = await pg.connect();
          return {
            query: async <T>(sql: string, params?: unknown[]) => ({
              rows: (await c.query(postgresQuery(sql, params))).rows as T[],
            }),
            release: (error?: Error) => c.release(error),
          };
        },
        end: () => pg.end(),
      };
    }
  }
  return pool;
}
