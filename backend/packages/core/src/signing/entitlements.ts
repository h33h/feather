import { Failure } from '../shared/index';
import type { Profile } from './policy';

export const identityKeys = new Set([
  'application-identifier',
  'com.apple.developer.team-identifier',
  'get-task-allow',
  'keychain-access-groups',
]);
const wildcardKeys = new Set([
  'application-identifier',
  'keychain-access-groups',
  'com.apple.developer.ubiquity-kvstore-identifier',
  'com.apple.developer.icloud-container-identifiers',
  'com.apple.developer.ubiquity-container-identifiers',
  'com.apple.developer.associated-domains',
]);
const forbiddenKeys = new Set(['__proto__', 'prototype', 'constructor']);
function safeString(value: string) {
  return (
    value.length <= 65536 &&
    [...value].every((character) => {
      const point = character.codePointAt(0)!;
      return (
        point === 9 ||
        point === 10 ||
        point === 13 ||
        (point >= 32 && point <= 0xd7ff) ||
        (point >= 0xe000 && point <= 0xfffd) ||
        (point >= 0x10000 && point <= 0x10ffff)
      );
    })
  );
}
export function safeEntitlementValue(value: unknown, allowData = false): boolean {
  let remaining = 10000;
  function valid(current: unknown, depth: number): boolean {
    if (--remaining < 0 || depth > 16) return false;
    if (typeof current === 'boolean') return true;
    if (typeof current === 'number') return Number.isSafeInteger(current);
    if (typeof current === 'string') return safeString(current);
    if (Array.isArray(current))
      return current.length <= 1024 && Array.from(current).every((v) => valid(v, depth + 1));
    if (
      !current ||
      typeof current !== 'object' ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(current))
    )
      return false;
    const object = current as Record<string, unknown>;
    const keys = Object.keys(object);
    if (Object.hasOwn(object, '$isignData')) {
      return (
        allowData &&
        keys.length === 1 &&
        typeof object.$isignData === 'string' &&
        object.$isignData.length <= 65536 &&
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
          object.$isignData,
        ) &&
        Buffer.from(object.$isignData, 'base64').toString('base64') === object.$isignData
      );
    }
    return (
      keys.length <= 1024 &&
      keys.every(
        (key) =>
          key.length > 0 &&
          key.length <= 1024 &&
          !forbiddenKeys.has(key) &&
          safeString(key) &&
          valid(object[key], depth + 1),
      )
    );
  }
  return valid(value, 0);
}
export function entitlementPermitted(key: string, claim: unknown, ceiling: unknown): boolean {
  if (
    !key ||
    key.length > 1024 ||
    !safeString(key) ||
    forbiddenKeys.has(key) ||
    key === '$isignData' ||
    !safeEntitlementValue(claim) ||
    !safeEntitlementValue(ceiling, true)
  )
    return false;
  function subset(value: unknown, permission: unknown): boolean {
    if (typeof value !== typeof permission) return false;
    if (typeof value === 'string' && typeof permission === 'string') {
      return (
        value === permission ||
        (wildcardKeys.has(key) &&
          // Associated domain host wildcards are literal requested values (TN3155).
          (key === 'com.apple.developer.associated-domains' || !value.includes('*')) &&
          /^[^*]*\*$/.test(permission) &&
          value.startsWith(permission.slice(0, -1)) &&
          value.length > permission.length - 1)
      );
    }
    if (Array.isArray(value))
      return (
        Array.isArray(permission) &&
        value.every((entry) => permission.some((allowed) => subset(entry, allowed)))
      );
    if (value && typeof value === 'object') {
      if (
        !permission ||
        typeof permission !== 'object' ||
        Array.isArray(permission) ||
        Object.hasOwn(permission, '$isignData')
      )
        return false;
      return Object.entries(value).every(
        ([name, entry]) =>
          Object.hasOwn(permission, name) &&
          subset(entry, (permission as Record<string, unknown>)[name]),
      );
    }
    return value === permission;
  }
  return subset(claim, ceiling);
}
export function profileIdentityEntitlements(profile: Profile): Record<string, unknown> {
  const ent = profile.entitlements;
  const appId = profile.prefix + '.' + profile.bundleId;
  const permission = ent?.['application-identifier'];
  const suffix =
    typeof permission === 'string' && permission.startsWith(profile.prefix + '.')
      ? permission.slice(profile.prefix.length + 1)
      : '';
  if (
    !ent ||
    !safeEntitlementValue(ent, true) ||
    !(
      permission === appId ||
      (/^(?:[A-Za-z0-9-]+\.)*\*$/.test(suffix) &&
        entitlementPermitted('application-identifier', appId, permission))
    ) ||
    ent['com.apple.developer.team-identifier'] !== profile.teamId ||
    ent['get-task-allow'] !== false
  )
    throw new Failure('ENTITLEMENT_PROFILE_MISMATCH');
  const identity: Record<string, unknown> = {
    'application-identifier': appId,
    'com.apple.developer.team-identifier': profile.teamId,
    'get-task-allow': false,
  };
  if (Object.hasOwn(ent, 'keychain-access-groups')) {
    const groups = ent['keychain-access-groups'];
    if (
      !Array.isArray(groups) ||
      !groups.length ||
      new Set(groups).size !== groups.length ||
      !groups.every((group) => typeof group === 'string' && group.length > 0) ||
      !entitlementPermitted('keychain-access-groups', [appId], groups)
    )
      throw new Failure('ENTITLEMENT_PROFILE_MISMATCH');
    identity['keychain-access-groups'] = [appId];
  }
  return identity;
}
export function normalizedEntitlements(source: Record<string, unknown>, profile: Profile) {
  const output = profileIdentityEntitlements(profile);
  for (const [key, claim] of Object.entries(source)) {
    if (identityKeys.has(key)) continue;
    const ceiling = profile.entitlements[key];
    if (entitlementPermitted(key, claim, ceiling)) {
      output[key] = structuredClone(claim);
    } else if (Array.isArray(claim) && Array.isArray(ceiling) && safeEntitlementValue(claim)) {
      const retained = claim.filter((entry) => entitlementPermitted(key, [entry], ceiling));
      if (retained.length) output[key] = structuredClone(retained);
    }
  }
  const requestedGroups = source['keychain-access-groups'];
  if (Array.isArray(requestedGroups) && Array.isArray(output['keychain-access-groups'])) {
    const groups = output['keychain-access-groups'] as string[];
    for (const group of requestedGroups) {
      if (
        typeof group === 'string' &&
        group !== source['application-identifier'] &&
        !groups.includes(group) &&
        entitlementPermitted(
          'keychain-access-groups',
          [group],
          profile.entitlements['keychain-access-groups'],
        )
      )
        groups.push(group);
    }
  }
  return output;
}
