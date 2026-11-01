import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { DeviceCollection } from '../packages/core/src/devices/collection';
import { DeviceOnboarding } from '../packages/core/src/devices/onboarding';
import { nativeCollectionSession } from '../packages/core/src/application/native-device-session';
import { hash } from '../packages/core/src/shared';

async function fixture() {
  const db = await createDatabase();
  const now = 1000;
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner',1),('other','other',1)",
  );
  await db.query(
    "INSERT INTO native_sessions(id,owner_id,access_hash,verified_at,expires_at,refresh_expires_at) VALUES('native','owner',$1,1,99999,999999)",
    [hash('access')],
  );
  const onboarding = new DeviceOnboarding(
    db,
    {
      find: async () => [],
      register: async () => {
        throw Error('not requested');
      },
    },
    () => now,
  );
  let challenge = '';
  const collection = new DeviceCollection(
    db,
    onboarding,
    () => now,
    async () => ({
      challenge,
      udid: '00008030-0000000000000000',
      product: 'iPhone15,2',
      version: '18.0',
      signatureVerified: true,
      issuerTrusted: true,
      deviceCertificate: true,
    }),
    nativeCollectionSession,
  );
  return {
    db,
    collection,
    setChallenge(value: string) {
      challenge = value;
    },
  };
}
it('native device collection survives access-token refresh without a synthetic cookie', async () => {
  const f = await fixture();
  const c = await f.collection.challengeNative('owner', 'native');
  f.setChallenge(c.challenge);
  await f.db.query("UPDATE native_sessions SET access_hash=$1 WHERE id='native'", [
    hash('refreshed'),
  ]);
  await expect(f.collection.redeemProfile(c.challenge)).resolves.toHaveProperty(
    'challenge',
    c.challenge,
  );
  const result = await f.collection.callback(c.challenge, Buffer.from('trusted CMS fixture'));
  expect(result).toHaveProperty('status', 'collected');
  expect((await f.db.query('SELECT * FROM sessions')).rows).toHaveLength(0);
});
it('native collection rejects a foreign session and a logout before profile redemption', async () => {
  const f = await fixture();
  await expect(f.collection.challengeNative('other', 'native')).rejects.toThrow('SESSION_REQUIRED');
  const c = await f.collection.challengeNative('owner', 'native');
  await f.db.query("UPDATE native_sessions SET revoked_at=1000 WHERE id='native'");
  await expect(f.collection.redeemProfile(c.challenge)).rejects.toThrow(
    'PROFILE_LINK_EXPIRED_OR_USED',
  );
});
it('logout after profile download prevents the CMS callback from collecting a device', async () => {
  const f = await fixture();
  const c = await f.collection.challengeNative('owner', 'native');
  f.setChallenge(c.challenge);
  await f.collection.redeemProfile(c.challenge);
  await f.db.query("UPDATE native_sessions SET revoked_at=1000 WHERE id='native'");
  await expect(
    f.collection.callback(c.challenge, Buffer.from('trusted CMS fixture')),
  ).rejects.toThrow('CHALLENGE_EXPIRED_OR_USED');
  expect((await f.db.query('SELECT * FROM collected_devices')).rows).toHaveLength(0);
});
