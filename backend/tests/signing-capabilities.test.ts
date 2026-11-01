import { expect, it } from 'vitest';
import { createExecutorTask } from '../packages/core/src/signing/executor-task';
import type { Component, Profile } from '../packages/core/src/signing/policy';

const identity = {
  ownerId: 'owner',
  teamId: 'TEAM',
  prefix: 'PREFIX',
  fingerprint: 'A'.repeat(40),
  expiresAt: 999999,
  materialPath: 'materials/identity.p12',
};
function fixture(source: Record<string, unknown>, ceiling: Record<string, unknown>) {
  const component: Component = {
    kind: 'app',
    path: 'Payload/App.app',
    bundleId: 'com.example.app',
    platform: 'ios',
    architectures: ['arm64'],
    encrypted: false,
    minOs: '15.0',
    entitlements: source,
  };
  const profile: Profile & { materialPath: string } = {
    ...identity,
    bundleId: component.bundleId,
    udids: ['device'],
    materialPath: 'materials/profile.mobileprovision',
    entitlements: {
      'application-identifier': 'PREFIX.com.example.*',
      'com.apple.developer.team-identifier': 'TEAM',
      'get-task-allow': false,
      'keychain-access-groups': ['PREFIX.*', 'group.shared'],
      ...ceiling,
    },
  };
  return {
    ownerId: 'owner',
    components: [component],
    identity,
    profiles: { [component.bundleId]: profile },
    udid: 'device',
    targets: {},
    now: 10000,
  };
}
it('preserves framework identifiers that match inherited object property names', () => {
  for (const bundleId of ['constructor', 'toString']) {
    const input = fixture({}, {});
    input.components.push({
      ...input.components[0],
      kind: 'framework',
      bundleId,
      path: 'Payload/App.app/Frameworks/Example.framework',
      entitlements: {},
    });
    const result = createExecutorTask(input);
    expect(
      result.task.components.find((component) => component.kind === 'framework')?.bundleId,
    ).toBe(bundleId);
    expect(result.warnings).toEqual([]);
  }
});
it('preserves only source capabilities authorized by the signed profile ceiling', () => {
  const source = {
    'application-identifier': 'OLD.com.example.app',
    'get-task-allow': true,
    'keychain-access-groups': ['OLD.com.example.app', 'group.shared', 'foreign.shared'],
    'aps-environment': 'production',
    'com.apple.security.application-groups': ['group.shared'],
    'com.apple.developer.icloud-container-identifiers': ['iCloud.com.example.documents'],
    'com.apple.developer.icloud-services': ['CloudDocuments'],
    'com.example.structured': { enabled: true, modes: ['one'], version: 2 },
    'com.example.unavailable': true,
  };
  const input = fixture(source, {
    'aps-environment': 'production',
    'com.apple.security.application-groups': ['group.shared', 'group.extra'],
    'com.apple.developer.icloud-container-identifiers': ['iCloud.com.example.*'],
    'com.apple.developer.icloud-services': ['CloudDocuments', 'CloudKit'],
    'com.example.structured': { enabled: true, modes: ['one', 'two'], version: 2, unused: false },
    'com.example.profile-only': true,
  });
  const result = createExecutorTask(input);
  expect(result.task.profiles['com.example.app'].entitlements).toEqual(
    input.profiles['com.example.app'].entitlements,
  );
  expect(result.task.components[0].entitlements).toEqual({
    'application-identifier': 'PREFIX.com.example.app',
    'com.apple.developer.team-identifier': 'TEAM',
    'get-task-allow': false,
    'keychain-access-groups': ['PREFIX.com.example.app', 'group.shared'],
    'aps-environment': 'production',
    'com.apple.security.application-groups': ['group.shared'],
    'com.apple.developer.icloud-container-identifiers': ['iCloud.com.example.documents'],
    'com.apple.developer.icloud-services': ['CloudDocuments'],
    'com.example.structured': { enabled: true, modes: ['one'], version: 2 },
  });
  expect(
    result.warnings.filter((w) => w.code === 'CAPABILITY_REMOVED').map((w) => w.capability),
  ).toEqual(['get-task-allow', 'keychain-access-groups', 'com.example.unavailable']);
  expect(result.task.components[0].sourceEntitlements).toEqual(source);
});
it('does not treat arbitrary wildcard strings, booleans and integers as interchangeable grants', () => {
  for (const [value, permission] of [
    [true, 1],
    [1, true],
    ['anything', '*'],
    ['prefix.end.more', 'prefix.*.more'],
    [{ value: true }, { value: 1 }],
  ] as const) {
    const result = createExecutorTask(
      fixture({ 'com.example.claim': value }, { 'com.example.claim': permission }),
    );
    expect(result.task.components[0].entitlements).not.toHaveProperty('com.example.claim');
    expect(result.warnings).toContainEqual({
      code: 'CAPABILITY_REMOVED',
      componentPath: 'Payload/App.app',
      capability: 'com.example.claim',
    });
  }
});
it('retains authorized entries when only part of a capability list is permitted', () => {
  const result = createExecutorTask(
    fixture(
      {
        'com.apple.security.application-groups': ['group.shared', 'group.foreign'],
        'com.apple.developer.icloud-services': ['CloudDocuments', 'CloudKit'],
        'com.apple.developer.associated-domains': [
          'applinks:example.com',
          'webcredentials:other.com',
        ],
        'com.example.none': ['foreign'],
        'com.example.typed': [true, 1],
      },
      {
        'com.apple.security.application-groups': ['group.shared'],
        'com.apple.developer.icloud-services': ['CloudDocuments'],
        'com.apple.developer.associated-domains': ['applinks:*'],
        'com.example.none': ['allowed'],
        'com.example.typed': [1],
      },
    ),
  );
  expect(result.task.components[0].entitlements).toEqual({
    'application-identifier': 'PREFIX.com.example.app',
    'com.apple.developer.team-identifier': 'TEAM',
    'get-task-allow': false,
    'keychain-access-groups': ['PREFIX.com.example.app'],
    'com.apple.security.application-groups': ['group.shared'],
    'com.apple.developer.icloud-services': ['CloudDocuments'],
    'com.apple.developer.associated-domains': ['applinks:example.com'],
    'com.example.typed': [1],
  });
  expect(
    result.warnings.filter((w) => w.code === 'CAPABILITY_REMOVED').map((w) => w.capability),
  ).toEqual([
    'com.apple.security.application-groups',
    'com.apple.developer.icloud-services',
    'com.apple.developer.associated-domains',
    'com.example.none',
    'com.example.typed',
  ]);
});
it('rejects unsafe profile structures and removes unsafe source claims before signing', () => {
  for (const invalid of [
    null,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    { nested: null },
    '\u0000',
    { constructor: true },
  ]) {
    expect(() => createExecutorTask(fixture({}, { 'com.example.claim': invalid }))).toThrow();
    const result = createExecutorTask(fixture({ 'com.example.claim': invalid }, {}));
    expect(result.task.components[0].entitlements).not.toHaveProperty('com.example.claim');
    expect(result.warnings).toContainEqual({
      code: 'CAPABILITY_REMOVED',
      componentPath: 'Payload/App.app',
      capability: 'com.example.claim',
    });
  }
});
it('strips even profile-authorized capabilities from frameworks', () => {
  const input = fixture({}, { 'aps-environment': 'production' });
  input.components.push({
    ...input.components[0],
    kind: 'framework',
    path: 'Payload/App.app/Frameworks/Kit.framework',
    bundleId: 'com.example.kit',
    entitlements: { 'aps-environment': 'production' },
  });
  const result = createExecutorTask(input);
  expect(result.task.components.find((c) => c.kind === 'framework')?.entitlements).toEqual({});
  expect(result.warnings).toContainEqual({
    code: 'CAPABILITY_REMOVED',
    componentPath: 'Payload/App.app/Frameworks/Kit.framework',
    capability: 'aps-environment',
  });
});

it('never emits plist data markers even when the profile authorizes identical data', () => {
  const marker = { $isignData: 'AA==' };
  const result = createExecutorTask(
    fixture({ 'com.example.data': marker }, { 'com.example.data': marker }),
  );
  expect(result.task.profiles['com.example.app'].entitlements['com.example.data']).toEqual(marker);
  expect(result.task.components[0].entitlements).not.toHaveProperty('com.example.data');
  expect(result.warnings).toContainEqual({
    code: 'CAPABILITY_REMOVED',
    componentPath: 'Payload/App.app',
    capability: 'com.example.data',
  });
});

it('regenerates the source private keychain identity when a wildcard also permits the old ID', () => {
  const result = createExecutorTask(
    fixture(
      {
        'application-identifier': 'PREFIX.old.app',
        'keychain-access-groups': ['PREFIX.old.app', 'group.shared'],
      },
      {},
    ),
  );
  expect(result.task.components[0].entitlements['keychain-access-groups']).toEqual([
    'PREFIX.com.example.app',
    'group.shared',
  ]);
  expect(result.warnings).toEqual([]);
});

it('preserves literal wildcard associated domains under an authorized array ceiling', () => {
  const requested = ['applinks:*.example.com'];
  for (const permission of [['*'], ['applinks:*'], ['applinks:*.example.com']]) {
    const result = createExecutorTask(
      fixture(
        { 'com.apple.developer.associated-domains': requested },
        { 'com.apple.developer.associated-domains': permission },
      ),
    );
    expect(
      result.task.components[0].entitlements['com.apple.developer.associated-domains'],
    ).toEqual(requested);
    expect(result.warnings).toEqual([]);
  }
});

it('keeps associated domain permission matching anchored and app identity wildcards concrete', async () => {
  const { entitlementPermitted } = await import('../packages/core/src/signing/entitlements');
  for (const permission of [
    ['webcredentials:*'],
    ['applinks:other.*'],
    ['applinks:*example.com'],
    '*',
  ]) {
    expect(
      entitlementPermitted(
        'com.apple.developer.associated-domains',
        ['applinks:*.example.com'],
        permission,
      ),
    ).toBe(false);
  }
  expect(entitlementPermitted('application-identifier', 'PREFIX.*.app', 'PREFIX.*')).toBe(false);
  expect(entitlementPermitted('keychain-access-groups', ['PREFIX.*.group'], ['PREFIX.*'])).toBe(
    false,
  );
});
