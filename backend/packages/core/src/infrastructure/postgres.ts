import { requireServer } from './config';
import { ProviderError } from '../shared/errors';
export interface SqlResult<T> {
  rows: T[];
  rowCount?: number | null;
}
export interface SqlConnection {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<SqlResult<T>>;
  release(error?: Error): void;
}
export interface SqlPool {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<SqlResult<T>>;
  connect(): Promise<SqlConnection>;
  end?(): Promise<void>;
}
export interface ProductionSql {
  query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<SqlResult<T>>;
  transaction<T>(work: (tx: Pick<ProductionSql, 'query'>) => Promise<T>): Promise<T>;
}
/** Inject a PostgreSQL TLS pool; all transaction statements use one checked-out connection. */
export class ProductionDatabase implements ProductionSql {
  #pool: SqlPool;
  constructor(pool: SqlPool) {
    requireServer();
    this.#pool = pool;
  }
  async query<T = Record<string, unknown>>(sql: string, params?: unknown[]) {
    try {
      return await this.#pool.query<T>(sql, params);
    } catch {
      throw new ProviderError('DATABASE_UNAVAILABLE');
    }
  }
  async transaction<T>(work: (tx: Pick<ProductionSql, 'query'>) => Promise<T>): Promise<T> {
    let connection: SqlConnection;
    try {
      connection = await this.#pool.connect();
    } catch {
      throw new ProviderError('DATABASE_UNAVAILABLE');
    }
    let broken: Error | undefined;
    let active = true;
    let callbackError: unknown;
    const tx: Pick<ProductionSql, 'query'> = {
      query: async <R = Record<string, unknown>>(sql: string, params?: unknown[]) => {
        if (!active) throw new ProviderError('TRANSACTION_CLOSED');
        try {
          return await connection.query<R>(sql, params);
        } catch {
          throw new ProviderError('DATABASE_UNAVAILABLE');
        }
      },
    };
    try {
      await connection.query('BEGIN');
      let result: T;
      try {
        result = await work(tx);
      } catch (error) {
        callbackError = error;
        throw error;
      }
      active = false;
      await connection.query('COMMIT');
      return result;
    } catch (error) {
      active = false;
      try {
        await connection.query('ROLLBACK');
      } catch {
        broken = new ProviderError('DATABASE_ROLLBACK_FAILED');
      }
      if (error instanceof ProviderError) throw error;
      if (callbackError === error) throw error;
      throw new ProviderError('DATABASE_UNAVAILABLE');
    } finally {
      active = false;
      connection.release(broken);
    }
  }
  async close() {
    await this.#pool.end?.();
  }
}
