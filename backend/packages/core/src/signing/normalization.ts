import type { Component, Identity, Profile } from './policy';
import type { SigningWarning } from '../shared/signing-contracts';
import { identityKeys, normalizedEntitlements } from './entitlements';

export function normalizeSigningInput<P extends Profile>(
  components: Component[],
  targets: Record<string, string>,
  profiles: Record<string, P>,
  _identity: Identity,
) {
  const warnings: SigningWarning[] = [];
  const normalizedProfiles = structuredClone(profiles);
  const normalized = components.map((component) => {
    const target = Object.hasOwn(targets, component.bundleId)
      ? targets[component.bundleId]
      : component.bundleId;
    if (target !== component.bundleId)
      warnings.push({
        code: 'BUNDLE_ID_CHANGED',
        componentPath: component.path,
        originalId: component.bundleId,
        targetId: target,
      });
    const codeOnly = component.kind === 'framework' || component.kind === 'dylib';
    const profile = normalizedProfiles[target];
    const entitlements =
      codeOnly || !profile ? {} : normalizedEntitlements(component.entitlements, profile);
    for (const [capability, value] of Object.entries(component.entitlements)) {
      let removed =
        codeOnly ||
        (!identityKeys.has(capability) &&
          (!Object.hasOwn(entitlements, capability) ||
            JSON.stringify(value) !== JSON.stringify(entitlements[capability])));
      if (!codeOnly && capability === 'get-task-allow' && value !== false) removed = true;
      if (!codeOnly && capability === 'keychain-access-groups') {
        const oldAppId = component.entitlements['application-identifier'];
        const groups = entitlements[capability];
        removed =
          !Array.isArray(value) ||
          !Array.isArray(groups) ||
          value.some((group) => group !== oldAppId && !groups.includes(group));
      }
      if (removed)
        warnings.push({ code: 'CAPABILITY_REMOVED', componentPath: component.path, capability });
    }
    return { ...component, bundleId: target, entitlements };
  });
  return { components: normalized, profiles: normalizedProfiles, warnings };
}
