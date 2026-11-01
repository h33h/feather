import { ownAuthority } from './helpers/seed-authority';
import { afterEach, expect, it } from 'vitest';
import { createDatabase, type Database } from './helpers/database';
import { DeviceOnboarding, type DeviceResource } from '../packages/core/src/devices/onboarding';
import { DeviceCollection } from '../packages/core/src/devices/collection';
import { hash, Failure } from '../packages/core/src/shared/index';
import { Service } from '../packages/core/src/application/service';

const databases: Database[] = [];
afterEach(async () => {
  await Promise.all(databases.splice(0).map((db) => db.close()));
});
const udid = '00008030-0000000000000000';
async function fixture() {
  const db = await createDatabase();
  databases.push(db);
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner@example.test',1),('other','other@example.test',1)",
  );
  await db.query(
    "INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,'owner','csrf',1,90000000)",
    [hash('owner-session')],
  );
  let now = 1000;
  let challenge = '';
  let remote: DeviceResource[] = [];
  let searches = 0;
  let beforeFind: (() => Promise<void>) | undefined;
  const api = {
    find: async () => {
      searches++;
      await beforeFind?.();
      return remote;
    },
    register: async () => {
      throw new Error('Automatic reconciliation must never register');
    },
  };
  const onboarding = new DeviceOnboarding(db, api, () => now);
  const service = new DeviceCollection(
    db,
    onboarding,
    () => now,
    async () => ({
      challenge,
      udid,
      product: 'iPhone15,2',
      version: '18.0',
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    }),
  );
  return {
    db,
    service,
    onboarding,
    get now() {
      return now;
    },
    advance(ms: number) {
      now += ms;
    },
    setRemote(value: DeviceResource[]) {
      remote = value;
    },
    get searches() {
      return searches;
    },
    beforeFind(fn: () => Promise<void>) {
      beforeFind = fn;
    },
    async collect() {
      const issued = await service.challenge('owner', 'owner-session');
      challenge = issued.challenge;
      return service.callback(challenge, Buffer.from('verified external CMS fixture'));
    },
    async ownConnection() {
      await db.query(
        "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('conn','owner','ABCDEFGHIJ','ready','asc')",
      );
      await ownAuthority(db);
    },
    setChallenge(value: string) {
      challenge = value;
    },
  };
}
it('collects and reveals an owner device before Apple without disclosing the UDID in lists', async () => {
  const f = await fixture();
  const collected = await f.collect();
  expect(collected.status).toBe('collected');
  expect((await f.service.list('owner'))[0]).toMatchObject({
    id: collected.id,
    udid: '••••0000',
    product: 'iPhone15,2',
    osVersion: '18.0',
    status: 'collected',
    bindings: [],
  });
  expect(await f.service.reveal('owner', collected.id)).toEqual({ id: collected.id, udid });
  expect(await f.service.list('other')).toEqual([]);
  await expect(f.service.reveal('other', collected.id)).rejects.toThrow('DEVICE_NOT_FOUND');
  expect((await f.db.query('SELECT * FROM devices')).rows).toEqual([]);
});
it('syncs a registered phone without a signing certificate and upgrades only after verified eligibility', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  f.setRemote([{ id: 'apple', status: 'ENABLED', certificateRequired: true }]);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  expect((await f.service.list('owner'))[0]).toMatchObject({
    status: 'certificate_required',
    bindings: [{ status: 'certificate_required' }],
  });
  expect((await f.db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status).toBe(
    'certificate_required',
  );
  expect((await f.db.query('SELECT * FROM device_registration_operations')).rows).toHaveLength(0);
  f.setRemote([{ id: 'apple', status: 'ENABLED', eligible: true }]);
  f.advance(120001);
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  expect((await f.service.list('owner'))[0].status).toBe('ready');
});
it('does not lose a known registration awaiting a certificate when Apple listing temporarily lags', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  const bound = (await f.service.list('owner'))[0].bindings[0];
  await f.db.query(
    "UPDATE devices SET status='certificate_required',apple_resource_id='apple' WHERE id=$1",
    [bound.deviceId],
  );
  await f.db.query(
    "INSERT INTO device_registration_operations(id,connection_id,connection_owner_id,generation,udid_hash,principal_id,device_id,state,resource_id,created_at) VALUES('operation','conn','owner',1,$1,'owner',$2,'complete','apple',1)",
    [hash(udid), bound.deviceId],
  );
  await f.db.query('UPDATE device_collection_checks SET next_check_at=0');
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  expect((await f.service.list('owner'))[0].status).toBe('certificate_required');
  expect(
    (await f.db.query<{ apple_resource_id: string }>('SELECT apple_resource_id FROM devices'))
      .rows[0].apple_resource_id,
  ).toBe('apple');
});
it('binds challenges to the live owner session and consumes each challenge once', async () => {
  const f = await fixture();
  const issued = await f.service.challenge('owner', 'owner-session');
  f.setChallenge(issued.challenge);
  await f.service.callback(issued.challenge, Buffer.from('verified'));
  await expect(f.service.callback(issued.challenge, Buffer.from('verified'))).rejects.toThrow(
    'CHALLENGE_EXPIRED_OR_USED',
  );
  const revoked = await f.service.challenge('owner', 'owner-session');
  f.setChallenge(revoked.challenge);
  await f.db.query('DELETE FROM sessions WHERE token_hash=$1', [hash('owner-session')]);
  await expect(f.service.callback(revoked.challenge, Buffer.from('verified'))).rejects.toThrow(
    'CHALLENGE_EXPIRED_OR_USED',
  );
  await expect(f.service.challenge('other', 'owner-session')).rejects.toThrow('SESSION_REQUIRED');
});
it('rejects expired and mismatched callbacks and untrusted CMS', async () => {
  const f = await fixture();
  const expired = await f.service.challenge('owner', 'owner-session');
  f.setChallenge(expired.challenge);
  f.advance(600001);
  await expect(f.service.callback(expired.challenge, Buffer.from('verified'))).rejects.toThrow(
    'CHALLENGE_EXPIRED_OR_USED',
  );
  const current = await f.service.challenge('owner', 'owner-session');
  f.setChallenge('b'.repeat(43));
  await expect(f.service.callback(current.challenge, Buffer.from('verified'))).rejects.toThrow(
    'INVALID_DEVICE_CALLBACK',
  );
  const deny = new DeviceCollection(
    f.db,
    f.onboarding,
    () => f.now,
    async () => ({
      challenge: current.challenge,
      udid,
      signatureVerified: true,
      issuerTrusted: false,
      deviceCertificate: true,
    }),
  );
  await expect(deny.callback(current.challenge, Buffer.from('plist'))).rejects.toThrow(
    'INVALID_DEVICE_CALLBACK',
  );
  expect(await f.service.list('owner')).toEqual([]);
});
it('limits active challenges and de-duplicates repeated verified device enrollment', async () => {
  const f = await fixture();
  const first = await f.collect();
  const second = await f.collect();
  expect(second.id).toBe(first.id);
  for (let i = 0; i < 10; i++) await f.service.challenge('owner', 'owner-session');
  await expect(f.service.challenge('owner', 'owner-session')).rejects.toThrow(
    'DEVICE_CHALLENGE_LIMIT',
  );
  expect(await f.service.list('owner')).toHaveLength(1);
});
it('finds a collected UDID in a newly ready team and uses eligibility without registration', async () => {
  const f = await fixture();
  const collected = await f.collect();
  await f.ownConnection();
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: false }]);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect((await f.service.list('owner'))[0]).toMatchObject({
    id: collected.id,
    status: 'apple_processing',
    bindings: [{ status: 'apple_processing', connectionId: 'conn' }],
  });
  f.advance(30001);
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  const listed = (await f.service.list('owner'))[0];
  expect(listed.status).toBe('ready');
  expect(
    (
      await f.db.query<{ status: string; apple_resource_id: string }>(
        'SELECT status,apple_resource_id FROM devices WHERE id=$1',
        [listed.bindings[0].deviceId],
      )
    ).rows[0],
  ).toEqual({ status: 'ready', apple_resource_id: 'remote' });
  expect((await f.db.query('SELECT * FROM device_registration_operations')).rows).toEqual([]);
});
it('persists not-registered state while preserving explicit slot consent registration', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  const listed = (await f.service.list('owner'))[0];
  expect(listed.status).toBe('not_registered');
  expect(listed.bindings[0].status).toBe('not_registered');
  await expect(f.onboarding.register('owner', listed.bindings[0].deviceId, false)).rejects.toThrow(
    'DEVICE_SLOT_CONSENT_REQUIRED',
  );
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect(f.searches).toBe(2); // one automatic find and one explicit consent check
  expect((await f.db.query('SELECT * FROM device_registration_operations')).rows).toEqual([]);
});
it('uses persistent leases to prevent two instances polling the same device', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let started: () => void = () => {};
  const beginning = new Promise<void>((resolve) => {
    started = resolve;
  });
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  f.beforeFind(async () => {
    started();
    await gate;
  });
  const first = f.service.reconcileOwner('owner');
  await beginning;
  const second = new DeviceCollection(f.db, f.onboarding, () => f.now);
  await second.reconcileOwner('owner');
  release();
  await first;
  expect(f.searches).toBe(1);
  expect((await f.service.list('owner'))[0].status).toBe('ready');
});
it('rejects a delayed result when the Apple connection generation changes', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  f.beforeFind(async () => {
    await f.db.query("UPDATE connections SET generation=2 WHERE id='conn'");
  });
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect(
    (await f.db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status,
  ).not.toBe('ready');
  expect((await f.service.list('owner'))[0].status).not.toBe('ready');
});
it('handles shared teams and suppresses readiness after access is revoked', async () => {
  const f = await fixture();
  await f.collect();
  await f.db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('shared','other','ABCDEFGHIJ','ready','asc')",
  );
  await f.db.query(
    "INSERT INTO apple_access_grants(id,connection_id,connection_owner_id,recipient_id,connection_generation,state,created_at) VALUES('grant','shared','other','owner',1,'accepted',1)",
  );
  await f.db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id,grant_id) VALUES('owner','shared','other','grant')",
  );
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect((await f.service.list('owner'))[0]).toMatchObject({
    status: 'ready',
    bindings: [{ shared: true, connectionId: 'shared' }],
  });
  await f.db.query("UPDATE apple_access_grants SET state='revoked',generation=2 WHERE id='grant'");
  expect((await f.service.list('owner'))[0]).toMatchObject({
    status: 'connection_unavailable',
    bindings: [],
  });
  expect((await f.service.reveal('owner', (await f.service.list('owner'))[0].id)).udid).toBe(udid);
});
it('backs off ambiguous Apple results and preserves the collected identity', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  f.setRemote([
    { id: 'a', status: 'ENABLED' },
    { id: 'b', status: 'ENABLED' },
  ]);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect(f.searches).toBe(1);
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  expect(f.searches).toBe(1);
  f.advance(30001);
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  expect(f.searches).toBe(2);
  expect((await f.service.list('owner'))[0].status).toBe('collected');
  expect(
    (await f.db.query<{ failures: number }>('SELECT failures FROM device_collection_checks'))
      .rows[0].failures,
  ).toBe(2);
});
it('removes signing readiness when a previously matched Apple device disappears', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  f.advance(300001);
  f.setRemote([]);
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  expect((await f.service.list('owner'))[0].status).toBe('not_registered');
  expect((await f.db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status).toBe(
    'collected',
  );
});
it('does not commit a ready Apple result after the persistent lease expires', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  f.beforeFind(async () => {
    f.advance(120001);
  });
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect(
    (await f.db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status,
  ).not.toBe('ready');
  expect((await f.service.list('owner'))[0].status).not.toBe('ready');
});
it('provides a single profile download capability bound to the originating live session', async () => {
  const f = await fixture();
  const issued = await f.service.challenge('owner', 'owner-session');
  expect(await f.service.redeemProfile(issued.challenge)).toEqual(issued);
  await expect(f.service.redeemProfile(issued.challenge)).rejects.toThrow(
    'PROFILE_LINK_EXPIRED_OR_USED',
  );
  const revoked = await f.service.challenge('owner', 'owner-session');
  await f.db.query('DELETE FROM sessions WHERE token_hash=$1', [hash('owner-session')]);
  await expect(f.service.redeemProfile(revoked.challenge)).rejects.toThrow(
    'PROFILE_LINK_EXPIRED_OR_USED',
  );
});
it('requests UDID and model without requesting management or extra identifying attributes', async () => {
  const { profileServiceXml } = await import('../packages/core/src/devices/onboarding');
  const xml = profileServiceXml('https://sign.example', 'a'.repeat(43));
  expect(xml).toContain('<string>PRODUCT</string>');
  expect(xml).not.toContain('<string>SERIAL</string>');
  expect(xml).not.toContain('<string>IMEI</string>');
  expect(xml).not.toContain('com.apple.mdm');
});
it('keeps an uncertain registration processing while Apple has not listed the submitted device yet', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  const bound = (await f.service.list('owner'))[0].bindings[0];
  await f.db.query("UPDATE devices SET status='registering' WHERE id=$1", [bound.deviceId]);
  await f.db.query(
    "INSERT INTO device_registration_operations(id,connection_id,connection_owner_id,generation,udid_hash,principal_id,device_id,state,created_at) VALUES('operation','conn','owner',1,$1,'owner',$2,'unknown',1)",
    [hash(udid), bound.deviceId],
  );
  f.advance(120001);
  await ownAuthority(f.db);
  await f.service.reconcileDue();
  expect((await f.service.list('owner'))[0].status).toBe('registering');
  expect(
    (
      await f.db.query<{ status: string }>('SELECT status FROM devices WHERE id=$1', [
        bound.deviceId,
      ])
    ).rows[0].status,
  ).toBe('registering');
});

it('restores a removed iPhone only after a fresh verified owner enrollment callback', async () => {
  const f = await fixture();
  const collected = await f.collect();
  await f.ownConnection();
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  const bound = (await f.service.list('owner'))[0].bindings[0];
  await new Service(f.db, { now: () => f.now }).removeDevice('owner', bound.deviceId);
  f.advance(300001);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect(
    (
      await f.db.query<{ status: string }>('SELECT status FROM devices WHERE id=$1', [
        bound.deviceId,
      ])
    ).rows[0].status,
  ).toBe('locally_removed');
  expect(await f.service.list('owner')).toEqual([]);
  await f.db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('other-conn','other','KLMNOPQRST','ready','asc')",
  );
  await f.db.query(
    "INSERT INTO devices(id,owner_id,connection_id,name,status,udid,udid_hash,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES('foreign','other','other-conn','Other phone','locally_removed',$1,$2,1,1,'old')",
    [udid, hash(udid)],
  );
  await f.db.query(
    "INSERT INTO devices(id,owner_id,connection_id,name,status,udid,udid_hash,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES('different','owner','conn','Different phone','locally_removed',$1,$2,1,1,'old')",
    ['00008030-1111111111111111', hash('00008030-1111111111111111')],
  );
  const fresh = await f.service.challenge('owner', 'owner-session');
  f.setChallenge(fresh.challenge);
  f.advance(1);
  expect(
    (await f.service.callback(fresh.challenge, Buffer.from('fresh verified enrollment'))).id,
  ).not.toBe(collected.id);
  expect(
    (
      await f.db.query<{
        status: string;
        selected: boolean;
        apple_resource_id: string | null;
        enrollment_verified_at: number;
        enrollment_cms_sha256: string;
      }>(
        'SELECT status,selected,apple_resource_id,enrollment_verified_at,enrollment_cms_sha256 FROM devices WHERE id=$1',
        [bound.deviceId],
      )
    ).rows[0],
  ).toEqual({
    status: 'collected',
    selected: false,
    apple_resource_id: null,
    enrollment_verified_at: 301002,
    enrollment_cms_sha256: hash('fresh verified enrollment'),
  });
  await f.service.reconcileOwner('owner');
  expect((await f.service.list('owner'))[0].bindings[0]).toMatchObject({
    deviceId: bound.deviceId,
    status: 'ready',
  });
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect((await f.service.list('owner'))[0].status).toBe('ready');
  expect(
    (
      await f.db.query<{ id: string; status: string }>(
        "SELECT id,status FROM devices WHERE id IN('foreign','different') ORDER BY id",
      )
    ).rows,
  ).toEqual([
    { id: 'different', status: 'locally_removed' },
    { id: 'foreign', status: 'locally_removed' },
  ]);
  expect((await f.db.query('SELECT * FROM device_registration_operations')).rows).toEqual([]);
});
it('rolls back Apple binding checks if seeding fails', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  const failCheck = (sql: string) => {
    if (sql.includes('INSERT INTO device_collection_checks'))
      throw new Error('Seeding interrupted');
  };
  const recording: Database = {
    query: async <T>(sql: string, params?: unknown[]) => {
      failCheck(sql);
      return f.db.query<T>(sql, params);
    },
    close: async () => {},
    transaction: (work) =>
      f.db.transaction((tx) =>
        work({
          query: async <T>(sql: string, params?: unknown[]) => {
            failCheck(sql);
            return tx.query<T>(sql, params);
          },
        }),
      ),
  };
  const service = new DeviceCollection(recording, f.onboarding, () => f.now);
  await expect(service.reconcileOwner('owner')).rejects.toThrow('Seeding interrupted');
  expect((await f.db.query('SELECT id FROM collected_devices')).rows).toHaveLength(1);
  expect((await f.db.query('SELECT id FROM device_collection_checks')).rows).toEqual([]);
});

it('retains a known Apple binding when eligibility profile reconciliation is incomplete', async () => {
  const f = await fixture();
  await f.collect();
  await f.ownConnection();
  f.setRemote([{ id: 'remote', status: 'ENABLED', eligible: true }]);
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  f.advance(300001);
  f.beforeFind(async () => {
    throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
  });
  await ownAuthority(f.db);
  await f.service.reconcileOwner('owner');
  expect((await f.service.list('owner'))[0].status).toBe('ready');
  expect(
    (
      await f.db.query<{ status: string; apple_resource_id: string }>(
        'SELECT status,apple_resource_id FROM devices',
      )
    ).rows[0],
  ).toEqual({ status: 'ready', apple_resource_id: 'remote' });
  expect(
    (
      await f.db.query<{ failures: number; last_error: string }>(
        'SELECT failures,last_error FROM device_collection_checks',
      )
    ).rows[0],
  ).toEqual({ failures: 1, last_error: 'RESOURCE_RECONCILIATION_REQUIRED' });
});
