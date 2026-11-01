import { ownAuthority } from './helpers/seed-authority';
import { it, expect } from 'vitest';
import { normalizeUdid, denyCms, DeviceOnboarding } from '../packages/core/src/devices/onboarding';
it('normalizes only supported UDIDs', () => {
  expect(normalizeUdid('00008030-0000000000000000')).toBe('00008030-0000000000000000');
  expect(() => normalizeUdid('foo')).toThrow('INVALID_UDID');
});
it('denies unsigned/default CMS', async () => {
  await expect(denyCms(Buffer.from('plist'))).rejects.toThrow('CMS_VERIFIER_UNAVAILABLE');
  const db = {
    query: async () => ({ rows: [] }),
    transaction: async () => {},
    close: async () => {},
  };
  const api = { find: async () => [], register: async () => ({ id: 'x', status: 'ENABLED' }) };
  await expect(
    new DeviceOnboarding(db as never, api, () => 1).callback('a'.repeat(43), Buffer.alloc(65537)),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
});
import { createDatabase } from './helpers/database';
it('consumes challenge once, selects and reconciles a device without a second slot', async () => {
  const db = await createDatabase();
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner@example.test',1)",
    );
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('conn','owner','ABCDEFGHIJ','ready','asc')",
    );
    let now = 1;
    let mutations = 0;
    let existing = false;
    const api = {
      find: async () =>
        existing ? [{ id: 'apple-device', status: 'ENABLED', eligible: true }] : [],
      register: async () => {
        mutations++;
        existing = true;
        return { id: 'apple-device', status: 'PROCESSING' };
      },
    };
    let callbackChallenge = '';
    const verifier = async () => ({
      challenge: callbackChallenge,
      udid: '00008030-0000000000000000',
      product: 'iPhone15,2',
      version: '18.0',
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    });
    await ownAuthority(db);
    const service = new DeviceOnboarding(db, api, () => now, verifier);
    const challenge = await service.challenge('owner', 'conn');
    callbackChallenge = challenge.challenge;
    const device = await service.callback(
      challenge.challenge,
      Buffer.from('synthetic CMS verifier fixture'),
    );
    await expect(service.callback(challenge.challenge, Buffer.from('synthetic'))).rejects.toThrow(
      'CHALLENGE_EXPIRED_OR_USED',
    );
    await expect(service.register('owner', device.id, false)).rejects.toThrow(
      'DEVICE_SLOT_CONSENT_REQUIRED',
    );
    expect((await service.register('owner', device.id, true)).status).toBe('apple_processing');
    expect((await service.register('owner', device.id, false)).status).toBe('ready');
    expect(mutations).toBe(1);
    await service.select('owner', device.id);
    expect(
      (
        await db.query<{ selected: boolean }>('SELECT selected FROM devices WHERE id=$1', [
          device.id,
        ])
      ).rows[0].selected,
    ).toBe(true);
    now += 600001;
    const expired = await service.challenge('owner', 'conn');
    callbackChallenge = expired.challenge;
    now += 600001;
    await expect(service.callback(expired.challenge, Buffer.from('synthetic'))).rejects.toThrow(
      'CHALLENGE_EXPIRED_OR_USED',
    );
  } finally {
    await db.close();
  }
});
import { profileServiceXml } from '../packages/core/src/devices/onboarding';
import { AppleProvisioningApi } from '../packages/core/src/apple/provisioning-client';
import { Failure } from '../packages/core/src/shared/index';
it('explicit sync records existing Apple membership without a certificate or a duplicate registration', async () => {
  const db = await createDatabase();
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('o','o@synthetic.invalid',1)",
    );
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
    );
    const api = new AppleProvisioningApi(
      {
        request: async (method) => {
          if (method !== 'GET') throw Error('UNEXPECTED_APPLE_MUTATION');
          return {
            data: [
              {
                id: 'apple',
                type: 'devices',
                attributes: { udid: 'A'.repeat(40), status: 'ENABLED', platform: 'IOS' },
              },
            ],
          };
        },
      },
      () => 1,
      async () => {
        throw new Failure('CERTIFICATE_REQUIRED', 409);
      },
    );
    await ownAuthority(db);
    const service = new DeviceOnboarding(db, api, () => 1),
      device = await fixtureDevice(db, 'o', 'c', {
        udid: 'A'.repeat(40),
        name: 'Synthetic iPhone',
        consent: true,
      });
    expect(await service.register('o', device.id, false)).toMatchObject({
      status: 'certificate_required',
    });
    expect(
      (
        await db.query<{ status: string; apple_resource_id: string }>(
          'SELECT status,apple_resource_id FROM devices',
        )
      ).rows,
    ).toEqual([{ status: 'certificate_required', apple_resource_id: 'apple' }]);
    expect((await db.query('SELECT * FROM device_registration_operations')).rows).toHaveLength(0);
  } finally {
    await db.close();
  }
});
it('issues fixed HTTPS ProfileService with bounded capability', () => {
  const result = profileServiceXml('https://sign.example', 'a'.repeat(43));
  expect(result).toContain('https://sign.example/api/devices/callback?challenge=');
  expect(result).toContain('<string>UDID</string>');
  expect(() => profileServiceXml('http://sign.example', 'a'.repeat(43))).toThrow();
  expect(() => profileServiceXml('https://sign.example/evil', 'a'.repeat(43))).toThrow();
  expect(() => profileServiceXml('https://sign.example', 'a'.repeat(43), 'x<script>')).toThrow();
});
it('rejects callbacks after reconnect and resets same UDID to new generation', async () => {
  const db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','o@test.example',1)");
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
    );
    let current = '';
    await ownAuthority(db);
    const svc = new DeviceOnboarding(
      db,
      { find: async () => [], register: async () => ({ id: 'a', status: 'ENABLED' }) },
      () => 1,
      async () => ({
        challenge: current,
        udid: 'A'.repeat(40),
        product: 'iPhone15,2',
        version: '18',
        signatureVerified: true,
        issuerTrusted: true,
        deviceCertificate: true,
      }),
    );
    current = (await svc.challenge('o', 'c')).challenge;
    await db.query("UPDATE connections SET generation=2 WHERE id='c'");
    await expect(svc.callback(current, Buffer.from('signed fixture'))).rejects.toThrow(
      'CHALLENGE_EXPIRED_OR_USED',
    );
    const device = await fixtureDevice(db, 'o', 'c', {
      udid: 'A'.repeat(40),
      name: 'My iPhone',
      consent: true,
    });
    await db.query("UPDATE devices SET status='ready',apple_resource_id='old' WHERE id=$1", [
      device.id,
    ]);
    await db.query("UPDATE connections SET generation=3 WHERE id='c'");
    current = (await svc.challenge('o', 'c')).challenge;
    expect((await svc.callback(current, Buffer.from('signed fixture'))).status).toBe('collected');
    expect(
      (
        await db.query<{ connection_generation: number; apple_resource_id: string | null }>(
          'SELECT * FROM devices WHERE id=$1',
          [device.id],
        )
      ).rows[0],
    ).toMatchObject({ connection_generation: 3, apple_resource_id: null });
  } finally {
    await db.close();
  }
});
it('binds factory to owner and allows only one concurrent registration POST', async () => {
  const db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','o@test.example',1)");
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
    );
    let posts = 0;
    const bindings: unknown[] = [];
    await ownAuthority(db);
    const svc = new DeviceOnboarding(
      db,
      async (binding) => {
        bindings.push(binding);
        return {
          find: async () => [],
          register: async () => {
            posts++;
            return { id: 'apple', status: 'PROCESSING' };
          },
        };
      },
      () => 1,
    );
    const device = await fixtureDevice(db, 'o', 'c', {
      udid: 'A'.repeat(40),
      name: 'phone',
      consent: true,
    });
    await Promise.allSettled([
      svc.register('o', device.id, true),
      svc.register('o', device.id, true),
    ]);
    expect(posts).toBe(1);
    expect(
      bindings.every(
        (b) =>
          JSON.stringify(b) === JSON.stringify({ ownerId: 'o', connectionId: 'c', generation: 1 }),
      ),
    ).toBe(true);
    await expect(svc.register('other', device.id, true)).rejects.toThrow('DEVICE_NOT_FOUND');
  } finally {
    await db.close();
  }
});
it('does not resurrect a device removed during polling or registration', async () => {
  const db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','o@test.example',1)");
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
    );
    let removeDuringFind = false;
    await ownAuthority(db);
    const svc = new DeviceOnboarding(
      db,
      async () => ({
        find: async () => {
          if (removeDuringFind) {
            await db.query("UPDATE devices SET status='locally_removed' WHERE owner_id='o'");
            return [{ id: 'apple', status: 'ENABLED', eligible: true }];
          }
          return [];
        },
        register: async () => {
          await db.query("UPDATE devices SET status='locally_removed' WHERE owner_id='o'");
          return { id: 'apple', status: 'ENABLED', eligible: true };
        },
      }),
      () => 1,
    );
    const device = await fixtureDevice(db, 'o', 'c', {
      udid: 'A'.repeat(40),
      name: 'phone',
      consent: true,
    });
    await expect(svc.register('o', device.id, true)).rejects.toThrow('CONNECTION_CHANGED');
    expect((await db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status).toBe(
      'locally_removed',
    );
    await db.query("UPDATE devices SET status='ready' WHERE owner_id='o'");
    removeDuringFind = true;
    await expect(svc.poll('o', device.id)).rejects.toThrow('CONNECTION_CHANGED');
    expect((await db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status).toBe(
      'locally_removed',
    );
  } finally {
    await db.close();
  }
});

// Trusted provenance fixtures for registration concurrency/removal tests; not a public enrollment API.
async function fixtureDevice(
  db: Awaited<ReturnType<typeof createDatabase>>,
  owner: string,
  connection: string,
  input: { udid: string; name: string; consent: boolean },
) {
  const device = crypto.randomUUID();
  const c = await db.query<{ generation: number }>(
    'SELECT generation FROM connections WHERE id=$1 AND owner_id=$2',
    [connection, owner],
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,name,status,udid,udid_hash,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES($1,$2,$3,$4,'collected',$5,$6,$7,1,$8)",
    [
      device,
      owner,
      connection,
      input.name,
      input.udid,
      (await import('../packages/core/src/application/service')).hash(input.udid),
      c.rows[0].generation,
      'a'.repeat(64),
    ],
  );
  await ownAuthority(db);
  return { id: device };
}
