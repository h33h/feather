import { nativeCollectionSession as validateNativeCollectionSession } from '../packages/core/src/application/native-device-session';
import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { DeviceCollection } from '../packages/core/src/devices/collection';
import type { DeviceOnboarding } from '../packages/core/src/devices/onboarding';
import { hash, token } from '../packages/core/src/shared/identifiers';
import { DeviceActions } from '../packages/core/src/devices/actions';

async function fixture() {
  const db = await createDatabase();
  const raw = token();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('u','user',1)");
  await db.query(
    "INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,'u','csrf',1,9999999)",
    [hash(raw)],
  );
  const collection = new DeviceCollection(
    db,
    {} as DeviceOnboarding,
    () => 1000,
    async (body) => ({
      ...JSON.parse(body.toString()),
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    }),
    validateNativeCollectionSession,
  );
  return { db, raw, collection };
}
it('collects an iPhone and iPad independently without replacing the first device', async () => {
  const { db, raw, collection } = await fixture();
  for (const [udid, product] of [
    ['a'.repeat(40), 'iPhone16,1'],
    ['b'.repeat(40), 'iPad14,1'],
  ]) {
    const { challenge } = await collection.challenge('u', raw);
    await collection.callback(
      challenge,
      Buffer.from(
        JSON.stringify({
          challenge,
          udid,
          product,
          version: '18.0',
        }),
      ),
    );
  }
  expect((await db.query('SELECT product FROM collected_devices ORDER BY product')).rows).toEqual([
    { product: 'iPad14,1' },
    { product: 'iPhone16,1' },
  ]);
  expect(await collection.list('u')).toHaveLength(2);
});
it('refreshes a verified identity proof without duplicating the same physical device', async () => {
  const { db, raw, collection } = await fixture();
  for (let attempt = 0; attempt < 2; attempt++) {
    const { challenge } = await collection.challenge('u', raw);
    await collection.callback(
      challenge,
      Buffer.from(
        JSON.stringify({
          challenge,
          udid: 'a'.repeat(40),
          product: 'iPhone16,1',
          version: '18.0',
        }),
      ),
    );
  }
  expect((await db.query('SELECT id FROM collected_devices')).rows).toHaveLength(1);
});
it('removes a collected identity even before it has an Apple device binding', async () => {
  const { db, raw, collection } = await fixture();
  const { challenge } = await collection.challenge('u', raw);
  const result = await collection.callback(
    challenge,
    Buffer.from(
      JSON.stringify({ challenge, udid: 'a'.repeat(40), product: 'iPhone16,1', version: '18.0' }),
    ),
  );
  await new DeviceActions(db, () => 1000).removeIdentity('u', result.id);
  expect((await db.query('SELECT id FROM collected_devices')).rows).toHaveLength(0);
});
