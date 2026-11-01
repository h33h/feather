import { PGlite } from '@electric-sql/pglite';
import { afterEach, expect, it } from 'vitest';
import type { Database } from '../packages/core/src/shared/database';

const engines: PGlite[] = [];
afterEach(async () => {
  await Promise.all(engines.splice(0).map((db) => db.close()));
});
function fresh() {
  const db = new PGlite();
  engines.push(db);
  return db;
}
async function initialize(db: PGlite) {
  const { initializeDatabase } = await import('../packages/core/src/infrastructure/database-init');
  await initializeDatabase(db as unknown as Database);
}
async function owner(db: PGlite, name: string) {
  await db.query('INSERT INTO users(id,login_name,created_at) VALUES($1,$1,1)', [name]);
}

it('initializes a fresh passkey database with roles and one Apple binding per user', async () => {
  const db = fresh();
  await expect(initialize(db)).resolves.toBeUndefined();
  await owner(db, 'owner');
  await owner(db, 'recipient');
  expect((await db.query('SELECT role,blocked_at FROM users WHERE id=$1', ['owner'])).rows).toEqual(
    [{ role: 'user', blocked_at: null }],
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','owner','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('owner','c','owner')",
  );
  await expect(
    db.query(
      "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('owner','c','owner')",
    ),
  ).rejects.toThrow();
  await expect(
    db.query(
      "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('recipient','c','owner')",
    ),
  ).rejects.toThrow();
});

it('rejects initialization on an occupied database without deleting its contents', async () => {
  const db = fresh();
  await db.exec("CREATE TABLE existing(value text); INSERT INTO existing VALUES('keep')");
  await expect(initialize(db)).rejects.toThrow('DATABASE_NOT_EMPTY');
  expect((await db.query('SELECT value FROM existing')).rows).toEqual([{ value: 'keep' }]);
});

it('allows new users beyond the retired three-account limit', async () => {
  const db = fresh();
  await initialize(db);
  const { PersonalAuth } = await import('../packages/core/src/auth/passkeys');
  const auth = new PersonalAuth(
    db as unknown as Database,
    'https://isign.example.test',
    () => 1000,
  );
  for (const name of ['one', 'two', 'three', 'four']) await auth.invite(name);
  expect(
    (await db.query<{ count: number }>('SELECT COUNT(*)::int AS count FROM users')).rows[0].count,
  ).toBe(4);
});

it('reserves the owner slot while receiving and bounds worker attempts to two', async () => {
  const db = fresh();
  await initialize(db);
  await owner(db, 'o');
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','App.ipa','u.ipa',0,'','receiving',1,99999)",
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,state,idempotency_key,created_at,updated_at) VALUES('j','o','u','receiving','first',1,1)",
  );
  await expect(
    db.query(
      "INSERT INTO jobs(id,owner_id,upload_id,state,idempotency_key,created_at,updated_at) VALUES('other','o','u','queued','second',1,1)",
    ),
  ).rejects.toThrow();
  await expect(db.query("UPDATE jobs SET attempts=3 WHERE id='j'")).rejects.toThrow();
  await db.query("UPDATE jobs SET state='cancelled',finished_at=2 WHERE id='j'");
  await expect(
    db.query(
      "INSERT INTO jobs(id,owner_id,upload_id,state,idempotency_key,created_at,updated_at) VALUES('other','o','u','queued','second',3,3)",
    ),
  ).resolves.toBeDefined();
});

it('allows multiple collected iPhone and iPad identities for one profile', async () => {
  const db = fresh();
  await initialize(db);
  await owner(db, 'o');
  for (const [id, product] of [
    ['phone', 'iPhone16,1'],
    ['tablet', 'iPad14,1'],
  ]) {
    await db.query(
      'INSERT INTO collected_devices(id,owner_id,name,udid,udid_hash,product,enrollment_verified_at,enrollment_cms_sha256,created_at,updated_at) VALUES($1,$2,$1,$1,$1,$3,1,$1,1,1)',
      [id, 'o', product],
    );
  }
  expect((await db.query('SELECT id FROM collected_devices ORDER BY id')).rows).toEqual([
    { id: 'phone' },
    { id: 'tablet' },
  ]);
});

it('uses the canonical personal schema through the memory test database factory', async () => {
  const { createDatabase } = await import('./helpers/pglite');
  const db = await createDatabase();
  try {
    await owner(db, 'factory-user');
    expect((await db.query('SELECT role FROM users')).rows).toEqual([{ role: 'user' }]);
  } finally {
    await db.close();
  }
});

it('bootstraps the first administrator once and never promotes an existing user implicitly', async () => {
  const db = fresh();
  await initialize(db);
  const { PersonalAuth } = await import('../packages/core/src/auth/passkeys');
  const auth = new PersonalAuth(
    db as unknown as Database,
    'https://isign.example.test',
    () => 1000,
  );
  const bootstrap = () => auth.bootstrapAdmin('admin');
  await expect(bootstrap()).resolves.toMatchObject({ ownerId: expect.any(String) });
  expect((await db.query('SELECT login_name,role FROM users')).rows).toEqual([
    { login_name: 'admin', role: 'admin' },
  ]);
  await expect(bootstrap()).rejects.toThrow('ADMIN_ALREADY_INITIALIZED');
  await auth.invite('normal');
  expect((await db.query("SELECT role FROM users WHERE login_name='normal'")).rows).toEqual([
    { role: 'user' },
  ]);
});
