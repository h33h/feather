import { loginFixture, connectionFixture, deviceFixture } from './helpers/login';
import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { RuntimeQueries } from '../packages/core/src/application/queries';
import { Service } from '../packages/core/src/application/service';
import { AppleSharing } from '../packages/core/src/apple/access';

it('Apple snapshot exposes the single effective connection and revokes recipient uploads immediately', async () => {
  const db = await createDatabase();
  const queries = new RuntimeQueries(db, () => 10000);
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner',1),('recipient','recipient',1)",
  );
  expect(await queries.apple('recipient')).toEqual({ connection: null, uploadAllowed: false });
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider,key_id) VALUES('c','owner','TEAM123','ready','asc','ABCDEFGHIJ')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('owner','c','owner')",
  );
  const connection = {
    id: 'c',
    team_id: 'TEAM123',
    state: 'ready',
    generation: 1,
    last_error: null,
    shared: false,
    key_id: '••••••GHIJ',
    identityReady: false,
  };
  expect(await queries.apple('owner')).toEqual({ connection, uploadAllowed: true });
  const profileId = (
    await db.query<{ public_profile_id: string }>(
      "SELECT public_profile_id FROM users WHERE id='recipient'",
    )
  ).rows[0].public_profile_id;
  const sharing = new AppleSharing(db, () => 10000);
  const { grantId } = await sharing.share('owner', profileId);
  expect(await queries.apple('recipient')).toEqual({
    connection: { ...connection, shared: true },
    uploadAllowed: true,
  });
  await sharing.revoke('owner', grantId);
  expect(await queries.apple('recipient')).toEqual({ connection: null, uploadAllowed: false });
  expect(await queries.apple('owner')).toEqual({ connection, uploadAllowed: true });
});

it('public readiness follows current connection generation without exposing full UDID', async () => {
  const db = await createDatabase();
  try {
    let code = '';
    const s = new Service(db, {
      now: () => 10000,
    });
    const login = await loginFixture(s.db, 'snapshot@example.invalid', s.now);
    const c = await connectionFixture(s.db, login.ownerId, 'TEAM-SNAPSHOT');
    const d = await deviceFixture(s.db, login.ownerId, c.id, 'Fixture', '18.0');
    const udid = 'A'.repeat(40);
    await db.query("UPDATE connections SET provider='asc' WHERE id=$1", [c.id]);
    await db.query(
      'UPDATE devices SET enrollment_verified_at=1,enrollment_cms_sha256=$2 WHERE id=$1',
      [d.id, 'a'.repeat(64)],
    );
    await db.query('UPDATE devices SET udid=$2,connection_generation=1 WHERE id=$1', [d.id, udid]);
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('snapshot-u',$1,'synthetic.ipa','synthetic.ipa',1,'synthetic','uploaded',0,999999)",
      [login.ownerId],
    );
    const j = await s.enqueue(login.ownerId, 'snapshot-u', 'snapshot');
    await db.query(
      "UPDATE jobs SET state='ready',device_id=$2,connection_id=$3,connection_generation=1 WHERE id=$1",
      [j.id, d.id, c.id],
    );
    await db.query(
      "INSERT INTO artifacts(id,owner_id,job_id,connection_id,connection_owner_id,device_id,object_key,digest,metadata,valid_until,created_at,expires_at,verified) VALUES('snapshot-a',$1,$2,$3,$1,$4,'synthetic-signed.ipa','synthetic',$5,999999,0,999999,true)",
      [login.ownerId, j.id, c.id, d.id, JSON.stringify({ generation: 1 })],
    );
    const queries = new RuntimeQueries(db, () => 10000);
    const before = await queries.library(login.ownerId);
    expect(before.artifacts[0].eligible).toBe(true);
    expect(JSON.stringify(before)).not.toContain(udid);
    await db.query('UPDATE connections SET generation=2 WHERE id=$1', [c.id]);
    const after = await queries.library(login.ownerId);
    const devices = await queries.devices(login.ownerId);
    expect(devices[0].status).toBe('connection_changed');
    expect(after.artifacts).toHaveLength(0);
    expect(JSON.stringify(after)).not.toContain(udid);
  } finally {
    await db.close();
  }
});
