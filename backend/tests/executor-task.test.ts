import { it, expect } from 'vitest';
import { createExecutorTask } from '../packages/core/src/signing/executor-task';
import type { Component } from '../packages/core/src/signing/policy';
it('projects approved mapped IDs and profiles into a digest-bound guest task', () => {
  const components: Component[] = [
    {
      kind: 'app',
      path: 'Payload/Fixture.app',
      bundleId: 'original.fixture',
      platform: 'ios',
      architectures: ['arm64'],
      encrypted: false,
      entitlements: {},
      minOs: '13.0',
    },
  ];
  const identity = {
    ownerId: 'owner',
    teamId: 'TEAM',
    prefix: 'TEAM',
    fingerprint: 'A'.repeat(40),
    expiresAt: 999999,
    materialPath: 'materials/identity.p12',
  };
  const profiles = {
    'mapped.fixture': {
      ...identity,
      bundleId: 'mapped.fixture',
      udids: ['synthetic-udid'],
      entitlements: {
        'application-identifier': 'TEAM.mapped.fixture',
        'com.apple.developer.team-identifier': 'TEAM',
        'get-task-allow': false,
      },
      materialPath: 'materials/profile.mobileprovision',
    },
  };
  const input = {
    ownerId: 'owner',
    components,
    identity,
    profiles,
    udid: 'synthetic-udid',
    deviceOs: '18.0',
    targets: { 'original.fixture': 'mapped.fixture' },

    now: 10000,
  };
  const result = createExecutorTask(input);
  expect(result.planDigest).toMatch(/^[a-f0-9]{64}$/);
  expect(result.task.components[0]).toMatchObject({
    sourceBundleId: 'original.fixture',
    bundleId: 'mapped.fixture',
    profileRequired: true,
  });
  expect(createExecutorTask(input).warnings.length).toBeGreaterThan(0);
  expect(() => createExecutorTask({ ...input, deviceOs: '12.0' })).toThrow('DEVICE_OS_TOO_OLD');
  expect(() =>
    createExecutorTask({ ...input, identity: { ...identity, materialPath: '../private-key.pem' } }),
  ).toThrow('GUEST_MATERIAL_PATH_INVALID');
});

function osFixture() {
  const identity = {
    ownerId: 'owner',
    teamId: 'TEAM',
    prefix: 'TEAM',
    fingerprint: 'A'.repeat(40),
    expiresAt: 999999,
    materialPath: 'materials/key.p12',
  };
  const components: Component[] = [
    {
      kind: 'app',
      path: 'Payload/Fixture.app',
      bundleId: 'test.fixture',
      platform: 'ios',
      architectures: ['arm64'],
      encrypted: false,
      entitlements: {},
      minOs: '17.0',
    },
  ];
  const profiles = {
    'test.fixture': {
      ...identity,
      bundleId: 'test.fixture',
      udids: ['synthetic-udid'],
      entitlements: {
        'application-identifier': 'TEAM.test.fixture',
        'com.apple.developer.team-identifier': 'TEAM',
        'get-task-allow': false,
      },
      materialPath: 'materials/profile.mobileprovision',
    },
  };
  return {
    ownerId: 'owner',
    components,
    identity,
    profiles,
    udid: 'synthetic-udid',
    targets: { 'test.fixture': 'test.fixture' },

    now: 10000,
  };
}
it('binds source extension removals into the plan and returns their loss warnings', () => {
  const input = osFixture();
  const removedExtensions = [
    {
      path: 'Payload/Fixture.app/PlugIns/Notification.appex',
      bundleId: 'test.fixture.notification',
      extensionPoint: 'com.apple.usernotifications.service',
    },
  ];
  const sourceWarnings = [
    {
      code: 'MIN_OS_CORRECTED' as const,
      componentPath: 'Payload/Fixture.app',
      originalMinOs: '16.0',
      targetMinOs: '17.0',
    },
  ];
  const result = createExecutorTask({ ...input, removedExtensions, sourceWarnings });
  expect(result.task).toHaveProperty('removedExtensions', removedExtensions);
  expect(result.planDigest).not.toBe(createExecutorTask(input).planDigest);
  expect(result.warnings).toEqual(
    expect.arrayContaining([
      sourceWarnings[0],
      {
        code: 'ENCRYPTED_EXTENSION_REMOVED',
        componentPath: removedExtensions[0].path,
        extensionPoint: 'com.apple.usernotifications.service',
      },
    ]),
  );
  expect(result.task.components).toHaveLength(1);
  expect(result.task.components[0].entitlements['application-identifier']).toBe(
    'TEAM.test.fixture',
  );
});

it('rejects removals outside the direct plugin directory or overlapping retained code', () => {
  const input = osFixture();
  for (const path of [
    'Payload/Fixture.app',
    'Payload/Other.app/PlugIns/Notification.appex',
    'Payload/Fixture.app/PlugIns/../Notification.appex',
  ]) {
    expect(() =>
      createExecutorTask({
        ...input,
        removedExtensions: [
          {
            path,
            bundleId: 'test.fixture.notification',
            extensionPoint: 'com.apple.usernotifications.service',
          },
        ],
      }),
    ).toThrow('SOURCE_REMOVALS_INVALID');
  }
});
for (const deviceOs of [undefined, null, '23A345'] as const)
  it('prepares a validated task when device OS is unknown: ' + String(deviceOs), () => {
    const result = createExecutorTask({ ...osFixture(), deviceOs });
    expect(result.task.components[0]).toMatchObject({
      minOs: '17.0',
      bundleId: 'test.fixture',
      profileRequired: true,
    });
    expect(result.task).not.toHaveProperty('deviceOs');
    expect(result.expiresAt).toBe(999999);
  });
it('does not bypass component minimum OS or profile validation when device OS is unknown', () => {
  const input = osFixture();
  expect(() =>
    createExecutorTask({
      ...input,
      deviceOs: null,
      components: [{ ...input.components[0], minOs: '23A345' }],
    }),
  ).toThrow();
  expect(() => createExecutorTask({ ...input, deviceOs: null, profiles: {} })).toThrow(
    'PROFILE_MISMATCH',
  );
  expect(() =>
    createExecutorTask({
      ...input,
      deviceOs: null,
      identity: { ...input.identity, ownerId: 'foreign' },
    }),
  ).toThrow('SIGNING_INPUT_REJECTED');
});
it('rejects known older semantic versions at the patch boundary', () => {
  const input = osFixture();
  const components = [{ ...input.components[0], minOs: '18.0.1' }];
  expect(() => createExecutorTask({ ...input, components, deviceOs: '18.0' })).toThrow(
    'DEVICE_OS_TOO_OLD',
  );
  expect(() => createExecutorTask({ ...input, components, deviceOs: '18.0.1' })).not.toThrow();
});
