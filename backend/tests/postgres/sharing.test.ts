import { afterEach, expect, it } from 'vitest';
import { postgresFixture } from '../helpers/postgres';
import { initializeDatabase } from '../../packages/core/src/infrastructure/database-init';
import { AppleSharing } from '../../packages/core/src/apple/access';
import { DatabaseOnboardingPort } from '../../packages/core/src/apple/onboarding';
import type { Vault } from '../../packages/core/src/apple/vault';

const fixtures: Awaited<ReturnType<typeof postgresFixture>>[] = [];
afterEach(async () => {
  await Promise.all(fixtures.splice(0).map((fixture) => fixture.close()));
});
it('serializes sharing and personal connection creation for the same recipient', async () => {
  const fixture = await postgresFixture();
  fixtures.push(fixture);
  const { db } = fixture;
  await initializeDatabase(db);
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1),('r','recipient',1)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
  );
  const profile = (
    await db.query<{ public_profile_id: string }>(
      "SELECT public_profile_id FROM users WHERE id='r'",
    )
  ).rows[0].public_profile_id;
  const sharing = new AppleSharing(db, () => 1000);
  const onboarding = new DatabaseOnboardingPort(db, {} as Vault, () => 1000);
  const results = await Promise.allSettled([sharing.share('o', profile), onboarding.begin('r')]);
  expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
  expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
  expect(
    (await db.query("SELECT user_id FROM user_apple_bindings WHERE user_id='r'")).rows,
  ).toHaveLength(1);
});
