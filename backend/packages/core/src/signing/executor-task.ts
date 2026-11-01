import { normalizeSigningInput } from './normalization';
import { Failure, hash } from '../shared/index';
import { buildPlan, type Component, type Identity, type Profile } from './policy';
import { canonicalReport } from '../shared/canonical-json';
import type { RemovedExtension, SigningWarning } from '../shared/signing-contracts';

export function validateSourceRemovals(components: Component[], removed: RemovedExtension[] = []) {
  const main = components.find((c) => c.kind === 'app');
  const points = new Set([
    'com.apple.usernotifications.service',
    'com.apple.usernotifications.content-extension',
    'com.apple.widgetkit-extension',
    'com.apple.widget-extension',
    'com.apple.share-services',
    'com.apple.ui-services',
  ]);
  if (!Array.isArray(removed) || removed.length > 20000)
    throw new Failure('SOURCE_REMOVALS_INVALID');
  if (removed.length && !main) throw new Failure('SOURCE_REMOVALS_INVALID');
  const seen = new Set<string>();
  for (const item of removed) {
    const prefix = main?.path + '/PlugIns/';
    if (
      !item ||
      Object.keys(item).sort().join(',') !== 'bundleId,extensionPoint,path' ||
      typeof item.path !== 'string' ||
      item.path.length > 4096 ||
      !item.path.startsWith(prefix) ||
      !/^[^/\\:]+\.appex$/.test(item.path.slice(prefix.length)) ||
      item.path.split('/').some((p) => !p || p === '.' || p === '..' || p.includes('\0')) ||
      typeof item.bundleId !== 'string' ||
      !/^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$/.test(item.bundleId) ||
      !item.bundleId.startsWith(main!.bundleId + '.') ||
      !points.has(item.extensionPoint) ||
      seen.has(item.path.toLowerCase()) ||
      components.some((c) => c.path === item.path || c.path.startsWith(item.path + '/'))
    )
      throw new Failure('SOURCE_REMOVALS_INVALID');
    seen.add(item.path.toLowerCase());
  }
}
type GuestIdentity = Identity & {
  materialPath: string;
};
type GuestProfile = Profile & {
  materialPath: string;
};
function materialPath(value: string) {
  if (!/^materials\/[A-Za-z0-9_-]+\.(p12|mobileprovision)$/.test(value))
    throw new Failure('GUEST_MATERIAL_PATH_INVALID');
  return value;
}
function version(value: string | null | undefined) {
  if (typeof value !== 'string' || !/^\d+(\.\d+){1,2}$/.test(value)) return null;
  const p = value.split('.').map(Number);
  return [p[0], p[1], p[2] ?? 0];
}
export function createExecutorTask(input: {
  ownerId: string;
  components: Component[];
  removedExtensions?: RemovedExtension[];
  sourceWarnings?: SigningWarning[];
  identity: GuestIdentity;
  profiles: Record<string, GuestProfile>;
  udid: string;
  deviceOs?: string | null;
  targets: Record<string, string>;

  now: number;
}) {
  validateSourceRemovals(input.components, input.removedExtensions);
  const device = version(input.deviceOs);
  for (const c of input.components) {
    const min = version(c.minOs);
    if (!min) throw new Failure('PLATFORM_UNSUPPORTED');
    if (device) {
      const unsupported =
        min[0] > device[0] ||
        (min[0] === device[0] &&
          (min[1] > device[1] || (min[1] === device[1] && min[2] > device[2])));
      if (unsupported) throw new Failure('DEVICE_OS_TOO_OLD');
    }
  }

  for (const source of Object.keys(input.targets))
    if (
      !input.components.some(
        (c) => c.bundleId === source && c.kind !== 'framework' && c.kind !== 'dylib',
      )
    )
      throw new Failure('MAPPING_GRAPH_MISMATCH');
  const normalized = normalizeSigningInput(
    input.components,
    input.targets,
    input.profiles,
    input.identity,
  );
  const plan = buildPlan(
    normalized.components,
    input.identity,
    input.udid,
    normalized.profiles,
    input.now,
    input.ownerId,
  );
  const task = {
    identity: { ...input.identity, materialPath: materialPath(input.identity.materialPath) },
    profiles: Object.fromEntries(
      Object.entries(normalized.profiles).map(([bid, p]) => [
        bid,
        { ...p, materialPath: materialPath(p.materialPath) },
      ]),
    ),
    udid: input.udid,
    ...(input.removedExtensions?.length
      ? { removedExtensions: structuredClone(input.removedExtensions) }
      : {}),

    components: plan.components.map((c) => ({
      ...c,
      sourceEntitlements: input.components.find((original) => original.path === c.path)!
        .entitlements,
      sourceBundleId: input.components.find((original) => original.path === c.path)!.bundleId,
    })),
  };
  return {
    task,
    planDigest: hash(canonicalReport(task)),
    expiresAt: plan.expiresAt,
    warnings: [
      ...(input.sourceWarnings ?? []).filter((w) => w.code !== 'ENCRYPTED_EXTENSION_REMOVED'),
      ...(input.removedExtensions ?? []).map((item): SigningWarning => ({
        code: 'ENCRYPTED_EXTENSION_REMOVED',
        componentPath: item.path,
        extensionPoint: item.extensionPoint,
      })),
      ...normalized.warnings,
    ],
  };
}
