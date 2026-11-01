import { it, expect } from 'vitest';
import { buildPlan, type Component } from '../packages/core/src/signing/policy';
import { hash } from '../packages/core/src/shared/index';
const component = (
  kind: Component['kind'] | 'dylib',
  path: string,
  bundleId: string,
): Component => ({
  kind,
  path,
  bundleId,
  platform: 'ios',
  architectures: ['arm64'],
  encrypted: false,
  entitlements: {},
  minOs: '18.0',
});
const app = component('app', 'Payload/Own.app', 'test.own');
const extension = component('appex', 'Payload/Own.app/PlugIns/Share.appex', 'test.own.share');
const framework = component('framework', 'Payload/Own.app/Frameworks/Core.framework', 'test.core');
const libraryPath = 'Payload/Own.app/Frameworks/libFixture.dylib';
const library = component('dylib', libraryPath, 'isign.dylib.' + hash(libraryPath));
const identity = {
  teamId: 'TEAM',
  prefix: 'PREFIX',
  fingerprint: 'A'.repeat(40),
  expiresAt: 999999,
  ownerId: 'owner',
};
function profile(bundleId: string) {
  return {
    ownerId: 'owner',
    bundleId,
    teamId: 'TEAM',
    prefix: 'PREFIX',
    fingerprint: 'A'.repeat(40),
    udids: ['TEST-DEVICE'],
    expiresAt: 999999,
    entitlements: {
      'application-identifier': 'PREFIX.' + bundleId,
      'com.apple.developer.team-identifier': 'TEAM',
      'get-task-allow': false,
      'keychain-access-groups': ['PREFIX.' + bundleId],
    },
  };
}
it('orders inner components first and keeps App ID Prefix distinct from Team ID', () => {
  const plan = buildPlan(
    [app, extension, framework],
    identity,
    'TEST-DEVICE',
    { [app.bundleId]: profile(app.bundleId), [extension.bundleId]: profile(extension.bundleId) },
    10000,
    'owner',
  );
  expect(plan.components.map((c) => c.kind)).toEqual(['framework', 'appex', 'app']);
  expect(
    plan.components.find((c) => c.kind === 'app')?.entitlements['application-identifier'],
  ).toBe('PREFIX.test.own');
  expect(plan.executionAuthorized).toBe(false);
});
it('signs standalone libraries before their app without provisioning profiles or entitlements', () => {
  const plan = buildPlan(
    [app, library],
    identity,
    'TEST-DEVICE',
    { [app.bundleId]: profile(app.bundleId) },
    10000,
    'owner',
  );
  expect(plan.components.map((c) => c.kind)).toEqual(['dylib', 'app']);
  expect(plan.components[0]).toMatchObject({
    bundleId: library.bundleId,
    profileRequired: false,
    entitlements: {},
  });
});
it('rejects library entitlements, renamed code identifiers and paths outside the app', () => {
  for (const change of [
    { entitlements: { 'get-task-allow': false } },
    { bundleId: 'test.other' },
    { path: 'Payload/Other.app/libFixture.dylib' },
  ])
    expect(() =>
      buildPlan(
        [app, { ...library, ...change }],
        identity,
        'TEST-DEVICE',
        { [app.bundleId]: profile(app.bundleId) },
        10000,
        'owner',
      ),
    ).toThrow();
});
it('rejects DRM, simulator, unknown entitlements and shared keychain without dropping claims', () => {
  for (const change of [
    { encrypted: true },
    { platform: 'simulator' },
    { architectures: ['x86_64'] },
    { entitlements: { 'com.apple.developer.icloud-container-identifiers': ['foreign'] } },
    {
      entitlements: {
        'application-identifier': 'OLD.test.own',
        'keychain-access-groups': ['OLD.shared'],
      },
    },
  ])
    expect(() =>
      buildPlan(
        [{ ...app, ...change }],
        identity,
        'TEST-DEVICE',
        { [app.bundleId]: profile(app.bundleId) },
        10000,
        'owner',
      ),
    ).toThrow();
});
it('rejects wrong owner, UDID, prefix, expiry and missing extension profile', () => {
  expect(() =>
    buildPlan(
      [app, extension],
      identity,
      'TEST-DEVICE',
      { [app.bundleId]: profile(app.bundleId) },
      10000,
      'owner',
    ),
  ).toThrow();
  for (const change of [
    { ownerId: 'foreign' },
    { prefix: 'TEAM' },
    { udids: [] },
    { expiresAt: 9999 },
  ])
    expect(() =>
      buildPlan(
        [app],
        identity,
        'TEST-DEVICE',
        { [app.bundleId]: { ...profile(app.bundleId), ...change } },
        10000,
        'owner',
      ),
    ).toThrow();
});

it('accepts safe single-segment framework IDs while keeping registered app IDs qualified', () => {
  const plan = buildPlan(
    [app, { ...framework, bundleId: 'FixtureKit' }],
    identity,
    'TEST-DEVICE',
    { [app.bundleId]: profile(app.bundleId) },
    10000,
    'owner',
  );
  expect(plan.components[0]).toMatchObject({
    bundleId: 'FixtureKit',
    profileRequired: false,
    entitlements: {},
  });
  for (const bundleId of [
    '',
    '.FixtureKit',
    'FixtureKit.',
    'Fixture..Kit',
    'Fixture_Kit',
    '../FixtureKit',
  ]) {
    expect(() =>
      buildPlan(
        [app, { ...framework, bundleId }],
        identity,
        'TEST-DEVICE',
        { [app.bundleId]: profile(app.bundleId) },
        10000,
        'owner',
      ),
    ).toThrow('COMPONENT_GRAPH_REJECTED');
  }
  for (const node of [
    { ...app, bundleId: 'FixtureApp' },
    { ...extension, bundleId: 'FixtureExtension' },
  ]) {
    expect(() =>
      buildPlan(
        node.kind === 'app' ? [node] : [app, node],
        identity,
        'TEST-DEVICE',
        {},
        10000,
        'owner',
      ),
    ).toThrow('COMPONENT_GRAPH_REJECTED');
  }
});
