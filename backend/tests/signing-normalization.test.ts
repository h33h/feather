import { expect, it } from 'vitest';
import type { Component, Identity, Profile } from '../packages/core/src/signing/policy';
it('removes unsupported capabilities with warnings and regenerates only authorized identity entitlements', async () => {
  const { normalizeSigningInput } = await import('../packages/core/src/signing/normalization');
  const identity: Identity = {
    ownerId: 'o',
    teamId: 'TEAM123',
    prefix: 'TEAM123',
    fingerprint: 'A'.repeat(40),
    expiresAt: 999999,
  };
  const component: Component = {
    kind: 'app',
    path: 'Payload/App.app',
    bundleId: 'com.example.app',
    platform: 'ios',
    architectures: ['arm64'],
    encrypted: false,
    minOs: '15.0',
    entitlements: {
      'application-identifier': 'OLD.com.example.app',
      'com.apple.developer.team-identifier': 'OLD',
      'get-task-allow': false,
      'keychain-access-groups': ['OLD.com.example.app', 'OLD.shared'],
      'aps-environment': 'production',
      'com.apple.security.application-groups': ['group.old'],
    },
  };
  const profile: Profile = {
    ...identity,
    bundleId: 'com.example.app',
    udids: ['device'],
    entitlements: {
      'application-identifier': 'TEAM123.com.example.app',
      'com.apple.developer.team-identifier': 'TEAM123',
      'get-task-allow': false,
      'keychain-access-groups': ['TEAM123.com.example.app'],
    },
  };
  const result = normalizeSigningInput(
    [component],
    { 'com.example.app': 'com.example.app' },
    { 'com.example.app': profile },
    identity,
  );
  expect(result.components[0].entitlements).toEqual(profile.entitlements);
  expect(result.warnings.map((w) => w.capability)).toEqual(
    expect.arrayContaining([
      'aps-environment',
      'com.apple.security.application-groups',
      'keychain-access-groups',
    ]),
  );
});
