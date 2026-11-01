import { Failure, hash } from '../shared/index';
import {
  entitlementPermitted,
  profileIdentityEntitlements,
  safeEntitlementValue,
} from './entitlements';
export interface Component {
  kind: 'app' | 'appex' | 'framework' | 'dylib';
  path: string;
  bundleId: string;
  platform: string;
  architectures: string[];
  encrypted: boolean;
  entitlements: Record<string, unknown>;
  minOs: string;
}
export interface Identity {
  ownerId: string;
  teamId: string;
  prefix: string;
  fingerprint: string;
  expiresAt: number;
}
export interface Profile extends Identity {
  bundleId: string;
  udids: string[];
  entitlements: Record<string, unknown>;
}
export function buildPlan(
  components: Component[],
  identity: Identity,
  udid: string,
  profiles: Record<string, Profile>,
  now: number,
  ownerId: string,
) {
  const mains = components.filter((c) => c.kind === 'app');
  if (
    mains.length !== 1 ||
    identity.ownerId !== ownerId ||
    identity.expiresAt <= now ||
    !/^[A-F0-9]{40,64}$/.test(identity.fingerprint)
  )
    throw new Failure('SIGNING_INPUT_REJECTED');
  const main = mains[0];
  if (!/^Payload\/[^/]+\.app$/.test(main.path)) throw new Failure('MAIN_APP_REQUIRED');
  const paths = new Set<string>();
  const ordered = [...components].sort(
    (a, b) => b.path.split('/').length - a.path.split('/').length || a.path.localeCompare(b.path),
  );
  const result = ordered.map((c) => {
    if (
      paths.has(c.path) ||
      c.path.split('/').some((p) => p === '..' || p === '.' || !p) ||
      c.path.includes('\\') ||
      (c !== main && !c.path.startsWith(main.path + '/')) ||
      !c.path.endsWith(
        { app: '.app', appex: '.appex', framework: '.framework', dylib: '.dylib' }[c.kind],
      ) ||
      (c.kind === 'dylib' && c.bundleId !== 'isign.dylib.' + hash(c.path)) ||
      !(
        c.kind === 'framework'
          ? /^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/
          : /^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$/
      ).test(c.bundleId)
    )
      throw new Failure('COMPONENT_GRAPH_REJECTED');
    paths.add(c.path);
    if (c.encrypted !== false) throw new Failure('DRM_UNSUPPORTED');
    if (
      c.platform !== 'ios' ||
      !c.architectures.includes('arm64') ||
      !/^\d+(\.\d+){1,2}$/.test(c.minOs)
    )
      throw new Failure('PLATFORM_UNSUPPORTED');
    if (!safeEntitlementValue(c.entitlements)) throw new Failure('UNSUPPORTED_ENTITLEMENT');
    if (c.kind === 'framework' || c.kind === 'dylib') {
      if (Object.keys(c.entitlements).length)
        throw new Failure(
          c.kind === 'dylib'
            ? 'DYLIB_ENTITLEMENTS_UNSUPPORTED'
            : 'FRAMEWORK_ENTITLEMENTS_UNVERIFIED',
        );
      if (c.kind === 'dylib' && profiles[c.bundleId]) throw new Failure('PROFILE_GRAPH_MISMATCH');
      return { ...c, entitlements: {}, profileRequired: false };
    }
    if (c.kind === 'appex' && !c.bundleId.startsWith(main.bundleId + '.'))
      throw new Failure('EXTENSION_ID_MISMATCH');
    const p = profiles[c.bundleId];
    if (
      !p ||
      p.ownerId !== ownerId ||
      p.bundleId !== c.bundleId ||
      p.teamId !== identity.teamId ||
      p.prefix !== identity.prefix ||
      p.fingerprint !== identity.fingerprint ||
      p.expiresAt <= now ||
      !p.udids.includes(udid)
    )
      throw new Failure('PROFILE_MISMATCH');
    const required = profileIdentityEntitlements(p);
    const entitlements = { ...required, ...c.entitlements };
    if (
      Object.entries(required).some(
        ([key, value]) => key !== 'keychain-access-groups' && entitlements[key] !== value,
      ) ||
      Object.entries(entitlements).some(
        ([key, value]) => !entitlementPermitted(key, value, p.entitlements[key]),
      )
    )
      throw new Failure('ENTITLEMENT_PROFILE_MISMATCH');
    return { ...c, entitlements, profileRequired: true };
  });
  return {
    components: result,
    executionAuthorized: false,
    verificationRequired: [
      'profile-CMS-chain',
      'certificate-key-match',
      'each-component-strict-codesign',
      'exact-entitlements',
      'exact-leaf',
      'current-lease',
      'current-connection-generation',
    ],
    expiresAt: Math.min(identity.expiresAt, ...Object.values(profiles).map((p) => p.expiresAt)),
  };
}
