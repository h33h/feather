import { it, expect } from 'vitest';
import { featherFixture } from './helpers/feather-assets';
const request = {
  deviceIds: ['d1', 'd2'],
  bundles: [
    { bundleId: 'com.example.app', entitlements: {} },
    { bundleId: 'com.example.app.extension', entitlements: {} },
  ],
};
it('returns verified exact-device profiles for app/extensions and caches by request', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  const a = await f.assets.profiles('o', request);
  expect(a.state).toBe('ready');
  expect(a.profiles.map((p) => p.bundleId)).toEqual(request.bundles.map((b) => b.bundleId));
  expect(a.profiles[0].deviceIds).toEqual(['d1', 'd2']);
  const posts = f.profilePosts;
  expect((await f.assets.profileStatus('o', a.operationId)).profiles).toEqual(a.profiles);
  await f.assets.profiles('o', request);
  expect(f.profilePosts).toBe(posts);
  await f.assets.profiles('o', { ...request, deviceIds: ['d1'] });
  expect(f.profilePosts).toBeGreaterThan(posts);
});
it('rejects unsupported capabilities before resource creation', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  await expect(
    f.assets.profiles('o', {
      deviceIds: ['d1'],
      bundles: [
        {
          bundleId: 'com.example.app',
          entitlements: { 'com.apple.security.application-groups': ['group.example'] },
        },
      ],
    }),
  ).rejects.toThrow('UNSUPPORTED_ENTITLEMENT');
  expect(f.profilePosts).toBe(0);
});
it.each([
  { teamId: 'FOREIGN1234' },
  { certificateSha256s: ['0'.repeat(64)] },
  { deviceUdids: ['A'.repeat(40)] },
  { deviceUdids: ['A'.repeat(40), 'B'.repeat(40), 'C'.repeat(40)] },
  { bundleId: 'com.foreign.app' },
  { expiresAt: 1 },
  { entitlements: { 'get-task-allow': true } },
])('rejects wrong CMS receipt %j', async (patch) => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  f.setReceipt(patch);
  await expect(f.assets.profiles('o', request)).rejects.toThrow('PROFILE_PROOF_MISMATCH');
});
it('reconciles ambiguous profile POST without blind retry', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  f.setAfterProfile(async () => {
    throw Error('timeout');
  });
  const a = await f.assets.profiles('o', request);
  expect(a.state).toBe('reconciling');
  const saved = f.profiles.splice(0);
  await f.assets.profileStatus('o', a.operationId);
  expect(f.profilePosts).toBe(1);
  f.profiles.push(...saved);
  f.setAfterProfile(async () => {});
  expect((await f.assets.profileStatus('o', a.operationId)).state).toBe('ready');
});
it('rejects removed device and foreign profile operation', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  const a = await f.assets.profiles('o', request);
  await f.db.query("UPDATE devices SET status='locally_removed' WHERE id='d2'");
  await expect(f.assets.profileStatus('o', a.operationId)).rejects.toThrow('DEVICE_NOT_READY');
  await expect(f.assets.profileStatus('m', a.operationId)).rejects.toThrow();
});
it('uses an existing explicit bundle and accepts only verified wildcard coverage of baseline entitlements', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  f.bundles.push({
    type: 'bundleIds',
    id: 'existing',
    attributes: { identifier: 'com.example.app' },
  });
  f.setReceipt({
    entitlements: {
      'application-identifier': 'ABCDEFGHIJ.com.example.*',
      'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
      'get-task-allow': false,
      'keychain-access-groups': ['ABCDEFGHIJ.*'],
    },
  });
  const result = await f.assets.profiles('o', {
    deviceIds: ['d1'],
    bundles: [
      {
        bundleId: 'com.example.app',
        entitlements: {
          'application-identifier': 'ABCDEFGHIJ.com.example.app',
          'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
          'get-task-allow': false,
          'keychain-access-groups': ['ABCDEFGHIJ.com.example.app'],
        },
      },
    ],
  });
  expect(result.state).toBe('ready');
  expect(JSON.parse(Buffer.from(result.profiles[0].profile, 'base64').toString()).bundleId).toBe(
    'existing',
  );
  expect(f.bundles).toHaveLength(1);
});
it('denies publication when a device is removed during attested CMS verification', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  const verify = f.assets.ports.verify;
  f.assets.ports.verify = async (input) => {
    const receipt = await verify(input);
    await f.db.query("UPDATE devices SET status='locally_removed' WHERE id='d1'");
    return receipt;
  };
  await expect(f.assets.profiles('o', request)).rejects.toThrow('DEVICE_NOT_READY');
  expect(
    (await f.db.query("SELECT id FROM feather_profile_operations WHERE state='ready'")).rows,
  ).toHaveLength(0);
});
it('renews an expired profile under a fresh operation without changing or revoking the identity', async () => {
  const f = await featherFixture();
  const identity = await f.assets.ensure('o'),
    first = await f.assets.profiles('o', request);
  f.advance(86400001);
  const second = await f.assets.profiles('o', request);
  expect(second.operationId).not.toBe(first.operationId);
  expect(second.state).toBe('ready');
  expect((await f.assets.status('o')).identityId).toBe(identity.identityId);
  expect(f.revokes).toBe(0);
});
it('reloads the journal when acquiring a lease after another worker submitted a profile', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  let releaseDevice!: () => void, deviceEntered!: () => void;
  const deviceGate = new Promise<void>((r) => (releaseDevice = r)),
    deviceReady = new Promise<void>((r) => (deviceEntered = r)),
    raw = f.api.rawDevice;
  f.api.rawDevice = async (...args) => {
    deviceEntered();
    await deviceGate;
    return raw(...args);
  };
  f.setAfterProfile(async () => {
    throw Error('timeout');
  });
  const first = f.assets.profiles('o', request);
  await deviceReady;
  const operation = (await f.db.query<{ id: string }>('SELECT id FROM feather_profile_operations'))
    .rows[0];
  let releaseFind!: () => void, findEntered!: () => void;
  const findGate = new Promise<void>((r) => (releaseFind = r)),
    findReady = new Promise<void>((r) => (findEntered = r)),
    find = f.api.findCertificates;
  f.api.findCertificates = async (spki) => {
    findEntered();
    await findGate;
    return find(spki);
  };
  const second = f.assets.profileStatus('o', operation.id);
  await findReady;
  releaseDevice();
  await first;
  f.profiles.length = 0;
  releaseFind();
  expect((await second).state).toBe('reconciling');
  expect(f.profilePosts).toBe(1);
});
it('explicit profile retry recovers only proven rejection while ordinary polling and maintenance do not retry', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  const create = f.api.profile;
  let attempts = 0;
  const { Failure } = await import('../packages/core/src/shared');
  f.api.profile = async () => {
    attempts++;
    throw new Failure('APPLE_OPERATION_REJECTED', 409);
  };
  const rejected = await f.assets.profiles('o', request);
  expect(rejected.state).toBe('action_required');
  await f.assets.profiles('o', request);
  await f.assets.maintain();
  expect(attempts).toBe(1);
  f.api.profile = create;
  const recovered = await f.assets.profiles('o', request, { retry: true });
  expect(recovered.state).toBe('ready');
  expect(recovered.operationId).toBe(rejected.operationId);
  expect(f.bundles).toHaveLength(1);
});
it('explicit profile retry cannot repeat unknown submission or undo certificate revoke', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  f.setAfterProfile(async () => {
    throw Error('timeout');
  });
  const rejected = await f.assets.profiles('o', request);
  f.profiles.length = 0;
  expect((await f.assets.profiles('o', request, { retry: true })).operationId).toBe(
    rejected.operationId,
  );
  expect(f.profilePosts).toBe(1);
  await f.assets.revoke('o');
  await expect(f.assets.profiles('o', request, { retry: true })).rejects.toThrow(
    'SIGNING_IDENTITY_NOT_READY',
  );
});
it('allows a current grant recipient to retry their own profiles without exposing their devices to the owner', async () => {
  const f = await featherFixture();
  await f.assets.ensure('o');
  const { AppleSharing } = await import('../packages/core/src/apple/access');
  const { Failure } = await import('../packages/core/src/shared');
  await f.db.query("UPDATE users SET public_profile_id=$1 WHERE id='m'", [
    'profile_' + 'b'.repeat(32),
  ]);
  const grant = await new AppleSharing(f.db, Date.now).share('o', 'profile_' + 'b'.repeat(32));
  await f.db.query(
    "UPDATE devices SET owner_id='m',access_grant_id=$1,access_grant_generation=1 WHERE id IN('d1','d2')",
    [grant.grantId],
  );
  const create = f.api.profile;
  f.api.profile = async () => {
    throw new Failure('APPLE_RATE_LIMITED', 409);
  };
  expect((await f.assets.profiles('m', request)).state).toBe('action_required');
  f.api.profile = create;
  await expect(f.assets.profiles('o', request, { retry: true })).rejects.toThrow(
    'DEVICE_NOT_READY',
  );
  expect((await f.assets.profiles('m', request, { retry: true })).state).toBe('ready');
});
it.each(['ready', 'unfinished'])(
  'pins wildcard scope after exact app/extension registration for a %s operation',
  async (state) => {
    const f = await featherFixture();
    await f.assets.ensure('o');
    if (state === 'unfinished')
      f.setAfterProfile(async () => {
        if (f.profilePosts === 2) throw Error('lost extension profile response');
      });
    const first = await f.assets.profiles('o', request);
    expect(first.state).toBe(state === 'ready' ? 'ready' : 'reconciling');
    expect(f.profilePosts).toBe(2);
    const wildcard = f.bundles.find((b) => b.attributes.identifier === '*')!;
    for (const bundle of request.bundles)
      f.bundles.push({
        type: 'bundleIds',
        id: 'exact-' + bundle.bundleId,
        attributes: { identifier: bundle.bundleId },
      });
    f.setAfterProfile(async () => {});
    const polled = await f.assets.profileStatus('o', first.operationId);
    expect(polled.state).toBe('ready');
    const requested = await f.assets.profiles('o', request);
    expect(requested.operationId).toBe(first.operationId);
    expect(requested.state).toBe('ready');
    expect(f.profilePosts).toBe(2);
    expect(
      requested.profiles.map(
        (p) => JSON.parse(Buffer.from(p.profile, 'base64').toString()).bundleId,
      ),
    ).toEqual([wildcard.id, wildcard.id]);
  },
);
