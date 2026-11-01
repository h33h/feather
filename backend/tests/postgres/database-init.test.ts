import { afterEach, expect, it } from 'vitest';
import { postgresFixture } from '../helpers/postgres';
import { initializeDatabase } from '../../packages/core/src/infrastructure/database-init';

const fixtures: Awaited<ReturnType<typeof postgresFixture>>[] = [];
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((fixture) => fixture.close()));
});
async function fresh() {
  const fixture = await postgresFixture();
  fixtures.push(fixture);
  return fixture.db;
}
it('serializes competing initializers without resetting the winner on PostgreSQL', async () => {
  const db = await fresh();
  const outcomes = await Promise.allSettled([initializeDatabase(db), initializeDatabase(db)]);
  expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
  expect(outcomes.filter((outcome) => outcome.status === 'rejected')).toHaveLength(1);
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('u','user',1)");
  await expect(initializeDatabase(db)).rejects.toThrow('DATABASE_NOT_EMPTY');
  expect((await db.query('SELECT id FROM users')).rows).toEqual([{ id: 'u' }]);
});
it('protects the single owner slot and worker attempt budget on PostgreSQL', async () => {
  const db = await fresh();
  await initializeDatabase(db);
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('u','user',1)");
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('s','u','App.ipa','s.ipa',0,'','receiving',1,99999)",
  );
  const insert = (id: string) =>
    db.query(
      "INSERT INTO jobs(id,owner_id,upload_id,state,idempotency_key,created_at,updated_at) VALUES($1,'u','s','receiving',$1,1,1)",
      [id],
    );
  const outcomes = await Promise.allSettled([insert('one'), insert('two')]);
  expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
  expect((await db.query('SELECT id FROM jobs')).rows).toHaveLength(1);
  await expect(db.query('UPDATE jobs SET attempts=3')).rejects.toThrow();
});
