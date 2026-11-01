import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { AppleSharing, resolveAppleAccess } from '../packages/core/src/apple/access';
import { resolveBinding } from '../packages/core/src/apple/bindings';
import { DatabaseOnboardingPort } from '../packages/core/src/apple/onboarding';
import type { Vault } from '../packages/core/src/apple/vault';
import { ConnectionLifecycle } from '../packages/core/src/apple/connection-lifecycle';
import { DeviceActions } from '../packages/core/src/devices/actions';
import { AccountLifecycle } from '../packages/core/src/auth/account-lifecycle';

async function fixture() {
  const db = await createDatabase();
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner',1),('recipient','recipient',1),('other','other',1)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','owner','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('owner','c','owner')",
  );
  const profile = (
    await db.query<{ public_profile_id: string }>(
      "SELECT public_profile_id FROM users WHERE id='recipient'",
    )
  ).rows[0].public_profile_id;
  return { db, profile, sharing: new AppleSharing(db, () => 1000) };
}

it('grants immediate access to the recipient’s single shared Apple binding', async () => {
  const { db, profile, sharing } = await fixture();
  const share = await sharing.share('owner', profile);
  expect(await resolveBinding(db, 'recipient')).toEqual({
    userId: 'recipient',
    connectionId: 'c',
    connectionOwnerId: 'owner',
    connectionGeneration: 1,
    grantId: share.grantId,
    grantGeneration: 1,
  });
  expect(await resolveAppleAccess(db, 'recipient', 'c', 1)).toEqual({
    ownerId: 'recipient',
    connectionId: 'c',
    connectionOwnerId: 'owner',
    generation: 1,
    accessGrantId: share.grantId,
    accessGrantGeneration: 1,
    teamId: 'TEAM123',
  });
});

it('refuses to replace an occupied recipient connection', async () => {
  const { db, profile, sharing } = await fixture();
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('own','recipient','RECIPIENT','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('recipient','own','recipient')",
  );
  await expect(sharing.share('owner', profile)).rejects.toThrow('APPLE_CONNECTION_EXISTS');
  expect((await resolveBinding(db, 'recipient'))?.connectionId).toBe('own');
});

it('requires disconnecting shared access before adding a personal Apple key', async () => {
  const { db, profile, sharing } = await fixture();
  await sharing.share('owner', profile);
  const onboarding = new DatabaseOnboardingPort(db, {} as Vault, () => 1000);
  await expect(onboarding.begin('recipient')).rejects.toThrow('APPLE_CONNECTION_EXISTS');
  expect((await resolveBinding(db, 'recipient'))?.connectionOwnerId).toBe('owner');
});
it('creates an own binding for an empty profile with the user as actual connection owner', async () => {
  const { db } = await fixture();
  const onboarding = new DatabaseOnboardingPort(db, {} as Vault, () => 1000);
  const connection = await onboarding.begin('other');
  expect(await resolveBinding(db, 'other')).toMatchObject({
    userId: 'other',
    connectionId: connection.id,
    connectionOwnerId: 'other',
    grantId: null,
  });
});

it('revokes the binding immediately and uses a new revision when shared again', async () => {
  const { db, profile, sharing } = await fixture();
  const first = await sharing.share('owner', profile);
  await sharing.revoke('owner', first.grantId);
  expect(await resolveBinding(db, 'recipient')).toBeNull();
  const second = await sharing.share('owner', profile);
  expect((await resolveBinding(db, 'recipient'))?.grantGeneration).toBe(2);
  expect(second.grantId).toBe(first.grantId);
});

it('denies a blocked owner or recipient rather than allocating shared access', async () => {
  const { db, profile, sharing } = await fixture();
  await db.query("UPDATE users SET blocked_at=1 WHERE id='recipient'");
  await expect(sharing.share('owner', profile)).rejects.toThrow('PROFILE_NOT_FOUND');
  expect(await resolveBinding(db, 'recipient')).toBeNull();
  await db.query("UPDATE users SET blocked_at=NULL WHERE id='recipient'");
  await db.query("UPDATE users SET blocked_at=1 WHERE id='owner'");
  await expect(sharing.share('owner', profile)).rejects.toThrow('CONNECTION_UNAVAILABLE');
});

it('lets a recipient disconnect shared access without deleting the owner connection', async () => {
  const { db, profile, sharing } = await fixture();
  await sharing.share('owner', profile);
  const lifecycle = new ConnectionLifecycle(db, () => 1000, {
    fresh: async () => ({ ownerId: 'recipient' }),
  });
  await lifecycle.disconnect('', '', '', '');
  expect(await resolveBinding(db, 'recipient')).toBeNull();
  expect((await resolveBinding(db, 'owner'))?.connectionId).toBe('c');
  expect((await db.query("SELECT state FROM connections WHERE id='c'")).rows).toEqual([
    { state: 'ready' },
  ]);
});

async function queuedSharedJob() {
  const context = await fixture();
  const { db, profile, sharing } = context;
  const { grantId } = await sharing.share('owner', profile);
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,access_grant_id,access_grant_generation,name,status,connection_generation,enrollment_verified_at) VALUES('d','recipient','c','owner',$1,1,'Phone','ready',1,1)",
    [grantId],
  );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','recipient','App.ipa','u.ipa',1,'digest','ready',1,999999)",
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_generation,connection_owner_id,access_grant_id,access_grant_generation,state,idempotency_key,created_at,updated_at) VALUES('j','recipient','u','d','c',1,'owner',$1,1,'queued','key',1,1)",
    [grantId],
  );
  return { ...context, grantId };
}

it('cancels queued shared work and requests source cleanup when access is revoked', async () => {
  const { db, sharing, grantId } = await queuedSharedJob();
  await sharing.revoke('owner', grantId);
  expect((await db.query('SELECT state,reason,finished_at FROM jobs')).rows).toEqual([
    { state: 'cancelled', reason: 'APPLE_SHARE_REVOKED', finished_at: 1000 },
  ]);
  expect((await db.query('SELECT delete_requested_at FROM uploads')).rows).toEqual([
    { delete_requested_at: 1000 },
  ]);
});

it('local device removal cancels its work without disconnecting the Apple team', async () => {
  const { db } = await queuedSharedJob();
  await new DeviceActions(db, () => 2000).removeDevice('recipient', 'd');
  expect((await db.query('SELECT state,reason,finished_at FROM jobs')).rows).toEqual([
    { state: 'cancelled', reason: 'DEVICE_REMOVED', finished_at: 2000 },
  ]);
  expect((await db.query('SELECT status FROM devices')).rows).toEqual([
    { status: 'locally_removed' },
  ]);
  expect((await resolveBinding(db, 'recipient'))?.connectionId).toBe('c');
});

it('deleting the owner closes recipient access and cancels dependent work', async () => {
  const { db } = await queuedSharedJob();
  const accounts = new AccountLifecycle(db, () => 3000, {
    fresh: async () => ({ ownerId: 'owner' }),
  });
  await accounts.deleteAccount('', '', '', '');
  expect(await resolveBinding(db, 'owner')).toBeNull();
  expect(await resolveBinding(db, 'recipient')).toBeNull();
  expect((await db.query('SELECT state,reason,finished_at FROM jobs')).rows).toEqual([
    { state: 'cancelled', reason: 'ACCOUNT_DELETED', finished_at: 3000 },
  ]);
});
