import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { featherFixture } from './helpers/feather-assets';
import { NativeSessions } from '../packages/core/src/auth/native-sessions';
import { NativeApplication } from '../packages/core/src/application/native-application';
import { token, hash } from '../packages/core/src/shared';

it('exchanges a fresh browser handoff and automatically prepares the isolated local signing bundle and profiles', async () => {
  const f = await featherFixture();
  const now = Date.now();
  f.setNow(now);
  const web = token(),
    verifier = token();
  await f.db.query(
    "INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,'o',$2,$3,$4)",
    [hash(web), hash(token()), now, now + 3600000],
  );
  const auth = new NativeSessions(f.db, {
    origin: 'https://isign.example.test',
    callback: 'isign-feather://auth/callback',
    now: () => now,
  });
  const start = await auth.start({
    state: token(),
    codeChallenge: createHash('sha256').update(verifier).digest('base64url'),
    redirectUri: 'isign-feather://auth/callback',
  });
  const callback = new URL((await auth.complete(start.transactionId, web)).callbackUrl);
  const session = await auth.exchange({
    transactionId: start.transactionId,
    code: callback.searchParams.get('code')!,
    codeVerifier: verifier,
    redirectUri: 'isign-feather://auth/callback',
  });
  const app = new NativeApplication({ auth, assets: f.assets } as never);
  await expect(app.command(session.accessToken, { kind: 'signing.ensure' })).resolves.toMatchObject(
    { state: 'ready', teamId: 'ABCDEFGHIJ' },
  );
  const bundle = await app.command(session.accessToken, { kind: 'signing.bundle' });
  expect(bundle).toMatchObject({ teamId: 'ABCDEFGHIJ', connectionId: 'c', revision: 1 });
  expect(bundle).toHaveProperty('p12');
  expect(bundle).not.toHaveProperty('privateKey');
  expect(bundle).not.toHaveProperty('p8');
  const result = await app.command(session.accessToken, {
    kind: 'signing.profiles',
    request: { deviceIds: ['d1'], bundles: [{ bundleId: 'com.example.app', entitlements: {} }] },
  });
  expect(result).toMatchObject({
    state: 'ready',
    profiles: [{ bundleId: 'com.example.app', teamId: 'ABCDEFGHIJ', deviceIds: ['d1'] }],
  });
  await auth.logout(session.accessToken);
  await expect(app.command(session.accessToken, { kind: 'signing.bundle' })).rejects.toThrow(
    'UNAUTHENTICATED',
  );
});
