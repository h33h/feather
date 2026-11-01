import { ReceiveDeviceCallback } from '../packages/core/src/application/receive-device-callback';
import { RequestAuthorization } from '../packages/core/src/application/request-authorization';
import { InstallationHistory } from '../packages/core/src/library/installation-history';
import { ownAuthority } from './helpers/seed-authority';
import { afterEach, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { createDatabase } from './helpers/database';
import { DeviceOnboarding } from '../packages/core/src/devices/onboarding';
import { hash } from '../packages/core/src/shared/index';
import { Service } from '../packages/core/src/application/service';
const state = vi.hoisted(() => ({ app: null as unknown }));
vi.mock('../server/runtime', () => ({
  origin: 'https://synthetic.invalid',
  runtime: async () => state.app,
}));
import { POST } from '../../web/src/app/api/[...path]/route';
const close: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const fn of close.splice(0)) await fn();
});
async function fixture(trusted = true) {
  const db = await createDatabase();
  close.push(() => db.close());
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner@synthetic.invalid',0)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('conn','owner','ABCDEFGHIJ','ready','asc')",
  );
  await db.query(
    'INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,$2,$3,0,999999)',
    [hash('s'.repeat(43)), 'owner', hash('c'.repeat(43))],
  );
  let current = '';
  const devices = new DeviceOnboarding(
    db,
    {
      find: async () => [],
      register: async () => {
        throw Error('MUST NEVER REGISTER FROM CALLBACK');
      },
    },
    () => 100,
    async () => ({
      challenge: current,
      udid: 'A'.repeat(40),
      signatureVerified: trusted,
      issuerTrusted: trusted,
      deviceCertificate: trusted,
    }),
  );
  await ownAuthority(db);
  current = (await devices.challenge('owner', 'conn', 's'.repeat(43))).challenge;
  const service = new Service(db, { now: () => 100 });
  const callback = new ReceiveDeviceCallback(undefined, devices);
  state.app = {
    devices,
    service,
    capabilities: { deviceEnrollment: true },
    receiveDeviceCallback: callback.run.bind(callback),
    authorization: new RequestAuthorization(db, () => 100),
    history: new InstallationHistory(db, () => 100),
  };
  return { db, current };
}
function callback(challenge: string, bytes: Buffer) {
  return new NextRequest('https://synthetic.invalid/api/devices/callback?challenge=' + challenge, {
    method: 'POST',
    headers: { host: 'synthetic.invalid', 'content-type': 'application/pkcs7-signature' },
    body: new Uint8Array(bytes),
  });
}
it('trusted callback saves UDID then returns Safari without installing a second profile or exposing identifiers', async () => {
  const h = await fixture();
  const result = await POST(callback(h.current, Buffer.from('SYNTHETIC CMS FIXTURE')));
  expect(result.status).toBe(301);
  expect(result.headers.get('location')).toBe('https://synthetic.invalid/');
  expect(result.headers.get('cache-control')).toBe('no-store');
  expect(result.headers.get('referrer-policy')).toBe('no-referrer');
  expect(await result.text()).toBe('');
  expect((await h.db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status).toBe(
    'collected',
  );
  expect((await h.db.query('SELECT * FROM device_registration_operations')).rows).toHaveLength(0);
  const replay = await POST(callback(h.current, Buffer.from('replay')));
  expect(replay.status).toBe(410);
  expect(replay.headers.get('location')).toBeNull();
});
it('untrusted CMS and oversized callbacks never consume provenance nonce', async () => {
  const h = await fixture(false);
  expect((await POST(callback(h.current, Buffer.from('UNTRUSTED')))).status).toBe(400);
  expect((await POST(callback(h.current, Buffer.alloc(65537)))).status).toBe(413);
  expect(
    (await h.db.query<{ consumed_at: number | null }>('SELECT consumed_at FROM device_challenges'))
      .rows[0].consumed_at,
  ).toBeNull();
  expect((await h.db.query('SELECT * FROM devices')).rows).toHaveLength(0);
});
it('callback session provenance expires and removed manual route cannot enroll authenticated users', async () => {
  const h = await fixture();
  await h.db.query('UPDATE sessions SET expires_at=50');
  expect((await POST(callback(h.current, Buffer.from('SYNTHETIC')))).status).toBe(410);
  await h.db.query('UPDATE sessions SET expires_at=999999');
  const manual = new NextRequest('https://synthetic.invalid/api/devices/manual', {
    method: 'POST',
    headers: {
      host: 'synthetic.invalid',
      origin: 'https://synthetic.invalid',
      cookie: '__Host-isign-session=' + 's'.repeat(43),
      'x-isign-csrf': 'c'.repeat(43),
      'content-type': 'application/json',
    },
    body: JSON.stringify({ udid: 'A'.repeat(40), name: 'manual', consent: true }),
  });
  expect((await POST(manual)).status).toBe(404);
  expect((await h.db.query('SELECT * FROM devices')).rows).toHaveLength(0);
});
