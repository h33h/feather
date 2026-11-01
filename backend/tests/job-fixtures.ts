import { createDatabase } from './helpers/database';
export async function createJobsFixture() {
  const db = await createDatabase();
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('o','o@example.test',1),('foreign','foreign@example.test',1)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES('d','o','c','o','phone','ready',1,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
  );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','app.ipa','o/u',1,'digest','ready',1,100000)",
  );
  return db;
}
