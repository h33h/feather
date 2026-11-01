import { afterAll, expect, it } from 'vitest';
import { createDatabase as createFreshDatabase } from './helpers/pglite';
import { TestDatabasePool } from './helpers/database';

const pools: TestDatabasePool[] = [];
afterAll(async () => {
  await Promise.all(pools.map((pool) => pool.close()));
});
function fixture() {
  let starts = 0;
  const pool = new TestDatabasePool(async () => {
    starts++;
    return createFreshDatabase();
  });
  pools.push(pool);
  return { pool, starts: () => starts };
}

it('reuses the engine while removing rows from the previous fixture', async () => {
  const f = fixture();
  const first = await f.pool.acquire();
  await first.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('old','old@example.test',1) ON CONFLICT(id) DO UPDATE SET login_name=excluded.login_name",
  );
  await first.close();
  const next = await f.pool.acquire();
  expect((await next.query('SELECT id FROM users')).rows).toEqual([]);
  expect(f.starts()).toBe(1);
  await next.close();
});

it('keeps simultaneous fixtures independent even when they use the same primary key', async () => {
  const f = fixture();
  const [first, second] = await Promise.all([f.pool.acquire(), f.pool.acquire()]);
  await first.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','a@example.test',1)",
  );
  await second.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','b@example.test',1)",
  );
  await first.close();
  expect((await second.query('SELECT login_name FROM users')).rows).toEqual([
    { login_name: 'b@example.test' },
  ]);
  expect(f.starts()).toBe(2);
  await second.close();
});

it('rejects stale queries after close and never returns a lease to the pool twice', async () => {
  const f = fixture();
  const first = await f.pool.acquire();
  await Promise.all([first.close(), first.close()]);
  const next = await f.pool.acquire();
  await expect(
    first.query("INSERT INTO users(id,login_name,created_at) VALUES('late','late@example.test',1)"),
  ).rejects.toThrow('TEST_DATABASE_CLOSED');
  expect((await next.query('SELECT id FROM users')).rows).toEqual([]);
  const concurrent = await f.pool.acquire();
  expect(f.starts()).toBe(2);
  await Promise.all([next.close(), concurrent.close()]);
});

it('discards engines after DDL so schema and role changes cannot reach the next test', async () => {
  const f = fixture();
  const first = await f.pool.acquire();
  await first.exec('ALTER TABLE users ADD COLUMN leaked text; CREATE ROLE fixture_role;');
  await first.close();
  const next = await f.pool.acquire();
  expect(
    (
      await next.query(
        "SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='leaked'",
      )
    ).rows,
  ).toEqual([]);
  expect(
    (await next.query("SELECT rolname FROM pg_roles WHERE rolname='fixture_role'")).rows,
  ).toEqual([]);
  expect(f.starts()).toBe(2);
  await next.close();
});

it('waits for an in-flight transaction before making its engine available again', async () => {
  const f = fixture();
  const first = await f.pool.acquire();
  let finish!: () => void;
  const gate = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const transaction = first.transaction(async (tx) => {
    await gate;
    await tx.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('old','old@example.test',1)",
    );
  });
  const closing = first.close();
  const concurrent = await f.pool.acquire();
  expect(f.starts()).toBe(2);
  finish();
  await Promise.all([transaction, closing]);
  const next = await f.pool.acquire();
  expect((await next.query('SELECT id FROM users')).rows).toEqual([]);
  await Promise.all([next.close(), concurrent.close()]);
});

it('restarts baseline sequences when the engine is reused', async () => {
  let starts = 0;
  const pool = new TestDatabasePool(async () => {
    starts++;
    const db = await createFreshDatabase();
    await db.exec('CREATE TABLE fixture_sequence(id serial PRIMARY KEY)');
    return db;
  });
  pools.push(pool);
  const first = await pool.acquire();
  expect(
    (await first.query('INSERT INTO fixture_sequence DEFAULT VALUES RETURNING id')).rows,
  ).toEqual([{ id: 1 }]);
  await first.close();
  const next = await pool.acquire();
  expect(
    (await next.query('INSERT INTO fixture_sequence DEFAULT VALUES RETURNING id')).rows,
  ).toEqual([{ id: 1 }]);
  expect(starts).toBe(1);
  await next.close();
});

it('releaseAll cleans forgotten leases and prevents their late writes', async () => {
  const f = fixture();
  const forgotten = await f.pool.acquire();
  await forgotten.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('old','old@example.test',1)",
  );
  await f.pool.releaseAll();
  await expect(forgotten.query('SELECT id FROM users')).rejects.toThrow('TEST_DATABASE_CLOSED');
  const next = await f.pool.acquire();
  expect((await next.query('SELECT id FROM users')).rows).toEqual([]);
  expect(f.starts()).toBe(1);
  await next.close();
});

it('cleanup waits for an acquisition that is still initializing', async () => {
  let start!: () => void;
  const gate = new Promise<void>((resolve) => {
    start = resolve;
  });
  const pool = new TestDatabasePool(async () => {
    await gate;
    return createFreshDatabase();
  });
  pools.push(pool);
  const acquiring = pool.acquire();
  let cleaned = false;
  const cleanup = pool.releaseAll().then(() => {
    cleaned = true;
  });
  await Promise.resolve();
  try {
    expect(cleaned).toBe(false);
  } finally {
    start();
  }
  const db = await acquiring;
  await cleanup;
  await expect(db.query('SELECT id FROM users')).rejects.toThrow('TEST_DATABASE_CLOSED');
});

it('shutdown closes an engine that finishes initializing after shutdown starts', async () => {
  let start!: () => void;
  const gate = new Promise<void>((resolve) => {
    start = resolve;
  });
  const pool = new TestDatabasePool(async () => {
    await gate;
    return createFreshDatabase();
  });
  pools.push(pool);
  const acquiring = pool.acquire();
  const closing = pool.close();
  start();
  await expect(acquiring).rejects.toThrow('TEST_DATABASE_POOL_CLOSED');
  await closing;
});

it('discards schema changes made through tagged-template transaction SQL', async () => {
  const f = fixture();
  const first = await f.pool.acquire();
  await first.transaction(async (tx) => {
    await tx.sql`ALTER TABLE users ADD COLUMN leaked text`;
  });
  await first.close();
  const next = await f.pool.acquire();
  expect(
    (
      await next.query(
        "SELECT column_name FROM information_schema.columns WHERE table_name='users' AND column_name='leaked'",
      )
    ).rows,
  ).toEqual([]);
  await next.close();
});
