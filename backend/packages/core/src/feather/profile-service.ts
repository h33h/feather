import { createHash } from 'node:crypto';
import type { ResolvedAppleAccess } from '../apple/access';
import { lockAuthority } from '../apple/access-lifecycle';
import { Failure, hash, id } from '../shared';
import { canonicalReport } from '../shared/canonical-json';
import type { ControlResource, VerifiedControlProfile } from '../devices/eligibility';
import { normalizeUdid } from '../devices/onboarding';
import type { FeatherSigningAssets, FeatherIdentity, FeatherSigningApi } from './signing-assets';
import { assetFailure, ASSET_LEASE_MS } from './operation-errors';
export type FeatherProfileRequest = {
  deviceIds: string[];
  bundles: { bundleId: string; entitlements: Record<string, unknown> }[];
};
export type FeatherProfile = {
  bundleId: string;
  profile: string;
  expiresAt: number;
  teamId: string;
  certificateSha256: string;
  deviceIds: string[];
};
export type FeatherProfileResult = {
  operationId: string;
  state: 'reconciling' | 'ready' | 'action_required';
  profiles: FeatherProfile[];
  reason?: string;
};
type ResourceState = { state: 'submitted' | 'complete' | 'rejected'; resource?: ControlResource };
type Operation = {
  id: string;
  owner_id: string;
  identity_id: string;
  binding: ResolvedAppleAccess;
  request: FeatherProfileRequest;
  state: string;
  resources: Record<string, ResourceState>;
  result: FeatherProfile[] | null;
  reason: string | null;
  lease_token: string | null;
  lease_until: number;
};
type Device = { id: string; udid: string; apple_resource_id: string };
const baseline = new Set([
  'application-identifier',
  'com.apple.developer.team-identifier',
  'keychain-access-groups',
  'get-task-allow',
]);
function permits(pattern: unknown, value: string) {
  return (
    typeof pattern === 'string' &&
    (pattern === value || (pattern.endsWith('.*') && value.startsWith(pattern.slice(0, -1))))
  );
}
function same(a: string[], b: string[]) {
  return (
    a.length === b.length &&
    new Set(a).size === a.length &&
    [...a].sort().every((v, i) => v === [...b].sort()[i])
  );
}
/** All CMS properties are taken from the attested verifier receipt, never decoded locally. */
export class FeatherProfileService {
  constructor(private assets: FeatherSigningAssets) {}
  private normalize(input: FeatherProfileRequest, b: ResolvedAppleAccess): FeatherProfileRequest {
    if (
      !input ||
      !Array.isArray(input.deviceIds) ||
      !input.deviceIds.length ||
      input.deviceIds.length > 100 ||
      new Set(input.deviceIds).size !== input.deviceIds.length ||
      input.deviceIds.some((v) => typeof v !== 'string' || v.length > 128) ||
      !Array.isArray(input.bundles) ||
      !input.bundles.length ||
      input.bundles.length > 64
    )
      throw new Failure('INVALID_PROFILE_REQUEST');
    const bundles = input.bundles.map((item) => {
      if (
        !item ||
        !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(item.bundleId) ||
        item.bundleId.length > 255 ||
        !item.entitlements ||
        typeof item.entitlements !== 'object' ||
        Array.isArray(item.entitlements)
      )
        throw new Failure('INVALID_PROFILE_REQUEST');
      for (const [key, value] of Object.entries(item.entitlements)) {
        if (!baseline.has(key)) throw new Failure('UNSUPPORTED_ENTITLEMENT', 422);
        if (key === 'get-task-allow' && value !== false)
          throw new Failure('UNSUPPORTED_ENTITLEMENT', 422);
        if (key === 'application-identifier' && value !== b.teamId + '.' + item.bundleId)
          throw new Failure('UNSUPPORTED_ENTITLEMENT', 422);
        if (key === 'com.apple.developer.team-identifier' && value !== b.teamId)
          throw new Failure('UNSUPPORTED_ENTITLEMENT', 422);
        if (
          key === 'keychain-access-groups' &&
          (!Array.isArray(value) ||
            !value.length ||
            value.length > 32 ||
            value.some(
              (v) => typeof v !== 'string' || !v.startsWith(b.teamId + '.') || v.length > 300,
            ))
        )
          throw new Failure('UNSUPPORTED_ENTITLEMENT', 422);
      }
      return {
        bundleId: item.bundleId,
        entitlements: JSON.parse(canonicalReport(item.entitlements)) as Record<string, unknown>,
      };
    });
    if (new Set(bundles.map((x) => x.bundleId)).size !== bundles.length)
      throw new Failure('INVALID_PROFILE_REQUEST');
    return { deviceIds: [...input.deviceIds].sort(), bundles };
  }
  private async devices(b: ResolvedAppleAccess, request: FeatherProfileRequest) {
    await this.assets.guard(b);
    const rows = (
      await this.assets.db.query<Device>(
        "SELECT id,udid,apple_resource_id FROM signing_devices WHERE owner_id=$1 AND connection_id=$2 AND connection_generation=$3 AND id=ANY($4::text[]) AND status='ready' AND enrollment_verified_at IS NOT NULL AND apple_resource_id IS NOT NULL AND udid IS NOT NULL",
        [b.ownerId, b.connectionId, b.generation, request.deviceIds],
      )
    ).rows;
    if (rows.length !== request.deviceIds.length) throw new Failure('DEVICE_NOT_READY', 409);
    return request.deviceIds.map((id) => {
      const d = rows.find((d) => d.id === id)!;
      return { ...d, udid: normalizeUdid(d.udid) };
    });
  }
  async profiles(
    ownerId: string,
    input: FeatherProfileRequest,
    options: { retry?: boolean } = {},
  ): Promise<FeatherProfileResult> {
    const b = await this.assets.binding(ownerId),
      request = this.normalize(input, b),
      identity = await this.assets.currentIdentity(b);
    await this.devices(b, request);
    const fingerprint = hash(canonicalReport({ binding: b, request }));
    const operation = await this.assets.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.assets.guard(b, tx);
      await tx.query(
        "UPDATE feather_profile_operations SET state='retired',fingerprint=fingerprint||':'||id,result=NULL WHERE owner_id=$1 AND identity_id=$2 AND fingerprint=$3 AND (state='retired' OR EXISTS(SELECT 1 FROM jsonb_array_elements(result) p WHERE (p->>'expiresAt')::bigint<=$4))",
        [ownerId, identity.id, fingerprint, this.assets.now()],
      );
      const result = await tx.query<Operation>(
        "INSERT INTO feather_profile_operations(id,owner_id,identity_id,binding,request,fingerprint,state,created_at) VALUES($1,$2,$3,$4,$5,$6,'pending',$7) ON CONFLICT(owner_id,identity_id,fingerprint) DO UPDATE SET fingerprint=EXCLUDED.fingerprint RETURNING *",
        [
          id(),
          ownerId,
          identity.id,
          JSON.stringify(b),
          JSON.stringify(request),
          fingerprint,
          this.assets.now(),
        ],
      );
      const operation = result.rows[0];
      if (
        options.retry === true &&
        operation.state === 'action_required' &&
        Number(operation.lease_until) <= this.assets.now()
      ) {
        const resources = Object.fromEntries(
          Object.entries(operation.resources).filter(
            ([, resource]) => resource.state !== 'rejected',
          ),
        );
        await tx.query(
          "UPDATE feather_profile_operations SET state='pending',reason=NULL,resources=$2 WHERE id=$1",
          [operation.id, JSON.stringify(resources)],
        );
      }
      return operation.id;
    });
    return this.status(ownerId, operation);
  }
  private dto(op: Operation): FeatherProfileResult {
    return {
      operationId: op.id,
      state:
        op.state === 'ready'
          ? 'ready'
          : op.state === 'action_required'
            ? 'action_required'
            : 'reconciling',
      profiles: op.state === 'ready' ? (op.result ?? []) : [],
      ...(op.reason ? { reason: op.reason } : {}),
    };
  }
  async status(ownerId: string, operationId: string): Promise<FeatherProfileResult> {
    let op = (
      await this.assets.db.query<Operation>(
        'SELECT * FROM feather_profile_operations WHERE id=$1 AND owner_id=$2',
        [operationId, ownerId],
      )
    ).rows[0];
    if (!op || op.state === 'retired') throw new Failure('PROFILE_OPERATION_UNAVAILABLE', 404);
    const b = op.binding;
    await this.assets.guard(b);
    const identity = await this.assets.currentIdentity(b);
    if (identity.id !== op.identity_id) throw new Failure('SIGNING_IDENTITY_CHANGED', 409);
    const devices = await this.devices(b, op.request),
      lease = id();
    const claim = await this.assets.db.query<Operation>(
      "UPDATE feather_profile_operations SET lease_token=$2,lease_until=$3 WHERE id=$1 AND lease_until<=$4 AND state IN('pending','ready') RETURNING *",
      [op.id, lease, this.assets.now() + ASSET_LEASE_MS, this.assets.now()],
    );
    if (!claim.rows.length)
      return this.dto({ ...op, state: op.state === 'ready' ? 'pending' : op.state });
    // The journal may have changed while Apple/authority checks were in flight.
    op = claim.rows[0];
    const guard = async () => {
      await this.assets.assertIdentity(b, identity);
      const current = await this.devices(b, op.request);
      if (canonicalReport(current) !== canonicalReport(devices))
        throw new Failure('DEVICE_NOT_READY', 409);
    };
    try {
      const api = await this.assets.ports.api(b);
      for (const d of devices) {
        const remote = await api.rawDevice(d.udid, d.apple_resource_id);
        await guard();
        if (!remote || remote.id !== d.apple_resource_id || remote.status !== 'ENABLED')
          throw new Failure('DEVICE_NOT_READY', 409);
      }
      const result: FeatherProfile[] = [];
      for (const item of op.request.bundles) {
        await guard();
        const bundle = await this.selectedBundle(op, lease, item.bundleId, api, guard);
        const name = 'feather-' + hash(op.id + ':' + item.bundleId).slice(0, 40);
        const profile = await this.resource(
          op,
          lease,
          'profile:' + item.bundleId,
          () => api.findProfiles(bundle.id, name),
          () =>
            api.profile({
              name,
              bundleId: bundle.id,
              certificateIds: [identity.certificate_id!],
              deviceIds: devices.map((d) => d.apple_resource_id),
            }),
          guard,
        );
        result.push(await this.verify(b, identity, item, devices, profile, guard));
      }
      await this.save(op, lease, "state='ready',result=$3,reason=NULL", [JSON.stringify(result)]);
      await guard();
      return { operationId: op.id, state: 'ready', profiles: result };
    } catch (error) {
      await guard();
      if (error instanceof Failure && error.code === 'RESOURCE_RECONCILIATION_REQUIRED')
        return { operationId: op.id, state: 'reconciling', profiles: [], reason: error.code };
      const reason = assetFailure(error);
      if (reason) {
        await this.save(op, lease, "state='action_required',reason=$3", [reason]);
        return { operationId: op.id, state: 'action_required', profiles: [], reason };
      }
      throw error;
    } finally {
      await this.assets.db.query(
        'UPDATE feather_profile_operations SET lease_token=NULL,lease_until=0 WHERE id=$1 AND lease_token=$2',
        [op.id, lease],
      );
    }
  }
  private async selectedBundle(
    op: Operation,
    lease: string,
    target: string,
    api: FeatherSigningApi,
    guard: () => Promise<void>,
  ) {
    const key = 'selected-bundle:' + target;
    const selected = op.resources[key]?.resource;
    if (selected) {
      const scope = selected.attributes.identifier;
      if (scope !== target && scope !== '*')
        throw new Failure('BUNDLE_OWNERSHIP_PROOF_INVALID', 403);
      // Reconcile the original selection, even if Apple now also has an exact ID.
      const bundle = await this.resource(
        op,
        lease,
        key,
        () => api.findBundles(scope),
        async () => {
          throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
        },
        guard,
      );
      if (bundle.attributes.identifier !== scope)
        throw new Failure('BUNDLE_OWNERSHIP_PROOF_INVALID', 403);
      return bundle;
    }
    // Persist the chosen resource before any profile POST can bind to it.
    const exact = await api.findBundles(target);
    await guard();
    if (exact.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    const scope = exact.length ? target : '*';
    const bundle =
      exact[0] ??
      (await this.resource(
        op,
        lease,
        'bundle:' + scope,
        () => api.findBundles(scope),
        () => api.bundle(scope, 'iSign Feather'),
        guard,
      ));
    if (bundle.attributes.identifier !== scope)
      throw new Failure('BUNDLE_OWNERSHIP_PROOF_INVALID', 403);
    op.resources[key] = { state: 'complete', resource: bundle };
    await this.save(op, lease, 'resources=$3', [JSON.stringify(op.resources)]);
    return bundle;
  }
  private async save(op: Operation, lease: string, set: string, values: unknown[]) {
    await this.assets.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.assets.guard(op.binding, tx);
      const r = await tx.query(
        `UPDATE feather_profile_operations SET ${set},lease_until=${this.assets.now() + ASSET_LEASE_MS} WHERE id=$1 AND lease_token=$2 AND lease_until>${this.assets.now()} AND state<>'retired' RETURNING id`,
        [op.id, lease, ...values],
      );
      if (!r.rows.length) throw new Failure('PROFILE_OPERATION_CHANGED', 409);
    });
  }
  private async resource(
    op: Operation,
    lease: string,
    key: string,
    find: () => Promise<ControlResource[]>,
    create: () => Promise<ControlResource>,
    guard: () => Promise<void>,
  ) {
    const prior = op.resources[key];
    if (prior?.state === 'rejected') throw new Failure('APPLE_OPERATION_REJECTED', 409);
    const matches = await find();
    await guard();
    if (matches.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    let resource = matches[0];
    if (prior?.resource && resource?.id !== prior.resource.id)
      throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
    if (!resource) {
      if (prior) throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      op.resources[key] = { state: 'submitted' };
      await this.save(op, lease, 'resources=$3', [JSON.stringify(op.resources)]);
      await guard();
      try {
        resource = await create();
      } catch (error) {
        if (assetFailure(error)) {
          op.resources[key] = { state: 'rejected' };
          await this.save(op, lease, 'resources=$3', [JSON.stringify(op.resources)]);
          throw error;
        }
        throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      }
    }
    await guard();
    op.resources[key] = { state: 'complete', resource };
    await this.save(op, lease, 'resources=$3', [JSON.stringify(op.resources)]);
    return resource;
  }
  private async verify(
    b: ResolvedAppleAccess,
    identity: FeatherIdentity,
    item: FeatherProfileRequest['bundles'][number],
    devices: Device[],
    resource: ControlResource,
    guard: () => Promise<void>,
  ): Promise<FeatherProfile> {
    const content = resource.attributes.profileContent;
    if (
      resource.attributes.profileState !== 'ACTIVE' ||
      resource.attributes.profileType !== 'IOS_APP_ADHOC' ||
      typeof content !== 'string' ||
      content.length > 87384 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(content)
    )
      throw new Failure('PROFILE_PROOF_MISMATCH', 409);
    const cms = Buffer.from(content, 'base64');
    if (!cms.length || cms.length > 65536 || cms.toString('base64') !== content)
      throw new Failure('PROFILE_PROOF_MISMATCH', 409);
    const digest = createHash('sha256').update(cms).digest('hex');
    const receipt = await this.assets.ports.verify({
      binding: b,
      cms,
      cmsSha256: digest,
      expected: {
        udid: devices[0].udid,
        certificateSha256: identity.certificate_sha256!,
        teamId: b.teamId,
        bundleId: item.bundleId,
      },
      now: this.assets.now(),
    });
    await guard();
    if (
      receipt.cmsSha256 !== digest ||
      receipt.teamId !== b.teamId ||
      receipt.bundleId !== item.bundleId ||
      receipt.profileType !== 'ad-hoc' ||
      !Number.isSafeInteger(receipt.expiresAt) ||
      receipt.expiresAt <= this.assets.now() ||
      receipt.expiresAt > Number(identity.expires_at) ||
      !Array.isArray(receipt.deviceUdids) ||
      !same(
        receipt.deviceUdids,
        devices.map((d) => d.udid),
      ) ||
      !Array.isArray(receipt.certificateSha256s) ||
      !same(receipt.certificateSha256s, [identity.certificate_sha256!]) ||
      !this.entitlements(receipt, item, b.teamId)
    )
      throw new Failure('PROFILE_PROOF_MISMATCH', 409);
    return {
      bundleId: item.bundleId,
      profile: content,
      expiresAt: receipt.expiresAt,
      teamId: b.teamId,
      certificateSha256: identity.certificate_sha256!,
      deviceIds: devices.map((d) => d.id),
    };
  }
  private entitlements(
    receipt: VerifiedControlProfile,
    item: FeatherProfileRequest['bundles'][number],
    teamId: string,
  ) {
    const ent = receipt.entitlements;
    if (
      !ent ||
      typeof ent !== 'object' ||
      !permits(ent['application-identifier'], teamId + '.' + item.bundleId) ||
      ent['com.apple.developer.team-identifier'] !== teamId ||
      ent['get-task-allow'] !== false
    )
      return false;
    // No additional capabilities have an Apple provisioning adapter yet.
    if (Object.keys(ent).some((k) => !baseline.has(k))) return false;
    const groups = ent['keychain-access-groups'];
    if (
      groups !== undefined &&
      (!Array.isArray(groups) ||
        groups.some((v) => typeof v !== 'string' || !v.startsWith(teamId + '.')))
    )
      return false;
    for (const [key, value] of Object.entries(item.entitlements)) {
      if (key === 'application-identifier') {
        if (!permits(ent[key], String(value))) return false;
      } else if (key === 'keychain-access-groups') {
        if (
          !Array.isArray(groups) ||
          !(value as string[]).every((v) => groups.some((g) => permits(g, v)))
        )
          return false;
      } else if (canonicalReport(ent[key]) !== canonicalReport(value)) return false;
    }
    return true;
  }
}
