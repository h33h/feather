import { Pool, types, type PoolConfig } from 'pg';
import { requireServer, type ServerSecret } from './config';
import { ProviderError } from '../shared/errors';
import { postgresQuery } from './postgres-query';
import type { SqlPool } from './postgres';
export function safeBigint(value: string) {
  if (!/^-?\d+$/.test(value)) throw new ProviderError('DATABASE_BIGINT_INVALID');
  const parsed = BigInt(value);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER) || parsed < BigInt(Number.MIN_SAFE_INTEGER))
    throw new ProviderError('DATABASE_BIGINT_OUT_OF_RANGE');
  return Number(parsed);
}
/** Creates a lazy real pg pool with verified TLS, scoped type parsers, and bounded waits. */
export function createPostgresPool(
  databaseUrl: ServerSecret,
  options: {
    ca?: string;
    maxConnections?: number;
    connectionTimeoutMs?: number;
    statementTimeoutMs?: number;
    poolConstructor?: typeof Pool;
  } = {},
): SqlPool {
  requireServer();
  let url: URL;
  try {
    url = new URL(databaseUrl.reveal());
  } catch {
    throw new ProviderError('DATABASE_CONFIG_INVALID');
  }
  if (
    !['postgres:', 'postgresql:'].includes(url.protocol) ||
    !url.hostname ||
    !url.pathname.slice(1) ||
    !['verify-full', 'verify-ca'].includes(url.searchParams.get('sslmode') ?? '')
  )
    throw new ProviderError('DATABASE_TLS_REQUIRED');
  // pg connection-string ssl options can override explicit TLS; remove them before construction.
  for (const key of [...url.searchParams.keys()])
    if (/^ssl|^uselibpqcompat$/i.test(key)) url.searchParams.delete(key);
  const max = options.maxConnections ?? 10,
    connectionTimeout = options.connectionTimeoutMs ?? 5000,
    statementTimeout = options.statementTimeoutMs ?? 30000;
  if (
    !Number.isInteger(max) ||
    max < 1 ||
    max > 100 ||
    ![connectionTimeout, statementTimeout].every(
      (value) => Number.isInteger(value) && value > 0 && value <= 120000,
    ) ||
    (options.ca !== undefined && (!options.ca.trim() || !options.ca.includes('BEGIN CERTIFICATE')))
  )
    throw new ProviderError('DATABASE_POOL_CONFIG_INVALID');
  const config: PoolConfig = {
    connectionString: url.href,
    ssl: { rejectUnauthorized: true, ...(options.ca ? { ca: options.ca } : {}) },
    max,
    connectionTimeoutMillis: connectionTimeout,
    idleTimeoutMillis: 10000,
    statement_timeout: statementTimeout,
    query_timeout: statementTimeout + 1000,
    idle_in_transaction_session_timeout: 10000,
    application_name: 'isign-service',
    types: {
      getTypeParser: (oid, format) =>
        oid === 20 && format !== 'binary' ? safeBigint : types.getTypeParser(oid, format),
    },
  };
  const PgPool = options.poolConstructor ?? Pool;
  let pool: Pool;
  try {
    pool = new PgPool(config);
  } catch {
    throw new ProviderError('DATABASE_POOL_CONFIG_INVALID');
  }
  pool.on('error', () => {});
  return {
    query: async <T>(sql: string, params?: unknown[]) => {
      const result = await pool.query(postgresQuery(sql, params));
      return { rows: result.rows as T[], rowCount: result.rowCount };
    },
    connect: async () => {
      const client = await pool.connect();
      return {
        query: async <T>(sql: string, params?: unknown[]) => {
          const result = await client.query(postgresQuery(sql, params));
          return { rows: result.rows as T[], rowCount: result.rowCount };
        },
        release: (error?: Error) => client.release(error),
      };
    },
    end: () => pool.end(),
  };
}
