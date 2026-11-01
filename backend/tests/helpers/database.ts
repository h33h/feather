import { afterAll, afterEach } from 'vitest';
import type { PGlite, Transaction } from '@electric-sql/pglite';
import { createDatabase as createFreshDatabase } from './pglite';
export type { Database, QueryDatabase } from '../../packages/core/src/shared/database';

type FixtureDatabase = Pick<PGlite, 'query' | 'exec' | 'transaction' | 'close'>;
type Engine = { db: PGlite; reset: string };
// Unusual SQL gets a fresh engine next time, rather than guessing how to undo it.
const changesState =
  /\b(create|alter|drop|grant|revoke|comment|prepare|execute|deallocate|listen|unlisten|begin|start|commit|rollback|vacuum|reindex|cluster|discard)\b|(?:^|;)\s*(do|set|reset)\b|\b(set_config|setval|lo_create|lo_import)\s*\(|\bpg_[a-z0-9_]+\b/i;

export class TestDatabasePool {
  private idle: Engine[] = [];
  private leases = new Set<() => Promise<void>>();
  private closed = false;
  private acquisitions = new Set<Promise<FixtureDatabase>>();
  private cleaning: Promise<void> | undefined;
  private shutdown: Promise<void> | undefined;
  constructor(private factory = createFreshDatabase) {}

  acquire(): Promise<FixtureDatabase> {
    if (this.closed) return Promise.reject(new Error('TEST_DATABASE_POOL_CLOSED'));
    if (this.cleaning) return Promise.reject(new Error('TEST_DATABASE_CLEANUP_IN_PROGRESS'));
    const result = this.borrow();
    this.acquisitions.add(result);
    void result.then(
      () => this.acquisitions.delete(result),
      () => this.acquisitions.delete(result),
    );
    return result;
  }

  private async borrow(): Promise<FixtureDatabase> {
    let engine = this.idle.pop();
    if (!engine) {
      const db = await this.factory();
      try {
        const tables = await db.query<{ tablename: string }>(
          "SELECT tablename FROM pg_tables WHERE schemaname='public'",
        );
        const names = tables.rows.map(
          ({ tablename }) => 'public."' + tablename.replaceAll('"', '""') + '"',
        );
        engine = { db, reset: `TRUNCATE ${names.join(',')} RESTART IDENTITY CASCADE` };
      } catch (error) {
        await db.close();
        throw error;
      }
    }
    if (this.closed) {
      await engine.db.close();
      throw new Error('TEST_DATABASE_POOL_CLOSED');
    }
    const { db, reset } = engine;
    let released = false;
    let dirty = false;
    let closing: Promise<void> | undefined;
    const pending = new Set<Promise<unknown>>();
    const inspect = (sql: string) => {
      dirty ||= changesState.test(sql);
    };
    const invoke = <T>(operation: () => Promise<T>): Promise<T> => {
      if (released) return Promise.reject(new Error('TEST_DATABASE_CLOSED'));
      const result = operation();
      pending.add(result);
      void result.then(
        () => pending.delete(result),
        () => pending.delete(result),
      );
      return result;
    };
    const close = () => {
      if (closing) return closing;
      released = true;
      closing = (async () => {
        await Promise.allSettled(pending);
        try {
          if (dirty || this.closed) {
            await db.close();
          } else {
            await db.exec('DISCARD ALL');
            await db.exec(reset);
            this.idle.push({ db, reset });
          }
        } catch (error) {
          await db.close();
          throw error;
        } finally {
          this.leases.delete(close);
        }
      })();
      return closing;
    };
    this.leases.add(close);
    return {
      query: ((...args: Parameters<PGlite['query']>) =>
        invoke(() => {
          inspect(args[0]);
          return db.query(...args);
        })) as PGlite['query'],
      exec: (...args) =>
        invoke(() => {
          inspect(args[0]);
          return db.exec(...args);
        }),
      transaction: (work) =>
        invoke(() =>
          db.transaction((tx) =>
            work(
              new Proxy(tx, {
                get(target, property) {
                  const member = Reflect.get(target, property, target);
                  if (typeof member !== 'function') return member;
                  return (...args: unknown[]) => {
                    if (
                      (property === 'query' || property === 'exec') &&
                      typeof args[0] === 'string'
                    )
                      inspect(args[0]);
                    if (property !== 'query' && property !== 'exec') dirty = true;
                    return Reflect.apply(member, target, args);
                  };
                },
              }) as Transaction,
            ),
          ),
        ),
      close,
    };
  }

  releaseAll(): Promise<void> {
    if (this.cleaning) return this.cleaning;
    const result = (async () => {
      await Promise.allSettled([...this.acquisitions]);
      await Promise.all([...this.leases].map((release) => release()));
    })();
    this.cleaning = result;
    void result.then(
      () => {
        this.cleaning = undefined;
      },
      () => {
        this.cleaning = undefined;
      },
    );
    return result;
  }
  close(): Promise<void> {
    if (this.shutdown) return this.shutdown;
    this.closed = true;
    this.shutdown = (async () => {
      await this.releaseAll();
      await Promise.all(this.idle.splice(0).map(({ db }) => db.close()));
    })();
    return this.shutdown;
  }
}

const pool = new TestDatabasePool(createFreshDatabase);
let cleaning = false;
let finished = false;
afterEach(async () => {
  cleaning = true;
  try {
    await Promise.all([pool.releaseAll()]);
  } finally {
    cleaning = false;
  }
});
afterAll(async () => {
  finished = true;
  await Promise.all([pool.close()]);
});
export function createDatabase() {
  if (finished || cleaning) throw new Error('TEST_DATABASE_FIXTURE_OUTSIDE_TEST');
  return pool.acquire();
}
