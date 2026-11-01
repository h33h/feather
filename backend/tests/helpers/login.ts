import type { Database } from '../../packages/core/src/shared/database';
import { id, token, hash, Failure } from '../../packages/core/src/shared/index';
/** Domain tests begin after WebAuthn verification; real WebAuthn is exercised separately. */
export async function loginFixture(db: Database, label: string, now: number) {
  const login = label.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 40);
  let user = (
    await db.query<{ id: string; deleted_at: number | null }>(
      'SELECT id,deleted_at FROM users WHERE login_name=$1',
      [login],
    )
  ).rows[0];
  if (user?.deleted_at !== null && user?.deleted_at !== undefined)
    throw new Failure('UNAUTHENTICATED', 401);
  if (!user) {
    user = { id: id(), deleted_at: null };
    await db.query('INSERT INTO users(id,login_name,created_at) VALUES($1,$2,$3)', [
      user.id,
      login,
      now,
    ]);
  }
  const raw = token(),
    csrf = token(),
    expiresAt = now + 7 * 86400000;
  await db.query(
    'INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,$2,$3,$4,$5)',
    [hash(raw), user.id, hash(csrf), now, expiresAt],
  );
  return { ownerId: user.id, token: raw, csrf, verifiedAt: now, expiresAt };
}
export async function connectionFixture(db: Database, owner: string, team: string) {
  const connection = id();
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES($1,$2,$3,'ready','asc')",
    [connection, owner, team],
  );
  await db.query(
    'INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES($1,$2,$1)',
    [owner, connection],
  );
  return { id: connection, generation: 1 };
}
export async function deviceFixture(
  db: Database,
  owner: string,
  connection: string,
  name: string,
  os: string,
) {
  const device = id(),
    udid = hash(device).slice(0, 40).toUpperCase();
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,os_version,udid,udid_hash,apple_resource_id,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES($1,$2,$3,$2,$4,'ready',$5,$6,$7,'apple-device',1,1,$8)",
    [device, owner, connection, name, os, udid, hash(udid), 'a'.repeat(64)],
  );
  return { id: device };
}
/** Explicit trusted seed data for domain fixtures; never install test-only database triggers. */
export async function bindOwnFixture(db: Database) {
  const connections = (
    await db.query<{ id: string; owner_id: string }>(
      "SELECT id,owner_id FROM connections WHERE state<>'disconnected' AND provider='asc' ORDER BY id",
    )
  ).rows;
  for (const connection of connections) {
    await db.query(
      'INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES($1,$2,$1) ON CONFLICT(user_id) DO NOTHING',
      [connection.owner_id, connection.id],
    );
  }
  for (const table of ['devices', 'jobs', 'artifacts', 'mappings']) {
    await db.query(
      'UPDATE ' +
        table +
        ' t SET connection_owner_id=t.owner_id WHERE t.connection_owner_id IS NULL AND EXISTS(SELECT 1 FROM connections c WHERE c.id=t.connection_id AND c.owner_id=t.owner_id)',
    );
  }
}
