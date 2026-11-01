import type { JobMaterialEnvelope } from '../shared/signing-contracts';
import { assertJobAccess } from '../apple/access-lifecycle';
import { createHash, X509Certificate } from 'node:crypto';
import type { Database } from '../shared/database';
import type { AppleProvisioningApi } from '../apple/provisioning-client';
import type { ControlResource } from '../devices/eligibility';
import type { ExecutorGrant } from '../shared/runner-contracts';
import { canonicalReport } from '../shared/canonical-json';
import { certificateTeamId, type BootstrapIdentity } from '../apple/onboarding';
import { Failure, hash } from '../shared/index';
import { normalizeUdid } from '../devices/onboarding';
import { Provisioning } from '../apple/provisioning';
import { ProfileRenewal } from '../apple/profile-renewal';
import type { PipelineProvisioner } from './pipeline';
import { createExecutorTask } from './executor-task';

export interface MaterialVault {
  prepareJobMaterial(
    grant: ExecutorGrant,
    secretId: string,
  ): Promise<{
    envelope: JobMaterialEnvelope;
    dataKey: Buffer;
  }>;
}
export interface SignedMaterialRpc {
  call<T>(operation: string, binding: ExecutorGrant, payload: unknown): Promise<T>;
}
type Options = {
  db: Database;
  api: (grant: ExecutorGrant) => Promise<AppleProvisioningApi>;
  vault: MaterialVault;
  rpc: SignedMaterialRpc;
  now?: () => number;
};
type Certificate = {
  id: string;
  pem: string;
  teamId: string;
  expiresAt: number;
};
/** Real Apple resource planner; private distribution key stays encrypted until the bound guest. */
export class ProductionProvisioner {
  constructor(private o: Options) {}
  private now() {
    return (this.o.now ?? Date.now)();
  }
  private async current(g: ExecutorGrant) {
    await assertJobAccess(this.o.db, g, this.now());
    const r = await this.o.db.query<{
      udid: string;
      os_version: string | null;
      apple_resource_id: string;
      team_id: string;
    }>(
      "SELECT d.udid,d.os_version,d.apple_resource_id,c.team_id FROM signing_jobs j JOIN users u ON u.id=j.owner_id JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=j.owner_id JOIN uploads a ON a.id=j.upload_id AND a.owner_id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$3 AND j.lease_expires>$4 AND j.state IN('analyzing','provisioning','signing','verifying') AND j.connection_id=$5 AND j.connection_generation=$6 AND c.id=$5 AND c.generation=$6 AND c.state='ready' AND c.provider='asc' AND d.id=$7 AND d.status='ready' AND d.connection_generation=c.generation AND a.digest=$8 AND a.expires_at>$4 AND u.deleted_at IS NULL",
      [
        g.jobId,
        g.ownerId,
        g.leaseToken,
        this.now(),
        g.connectionId,
        g.connectionGeneration,
        g.deviceId,
        g.uploadDigest,
      ],
    );
    if (!r.rows[0] || g.expiresAt <= this.now()) throw new Failure('STALE_EXECUTOR_LEASE', 409);
    const row = r.rows[0];
    if (!row.udid || !row.apple_resource_id) throw new Failure('DEVICE_NOT_READY', 409);
    return row;
  }
  async canPreserve(g: ExecutorGrant, bundleId: string) {
    await this.current(g);
    if (!/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(bundleId))
      throw new Failure('INVALID_BUNDLE_ID');
    const mapping = (
      await this.o.db.query<{ target_id: string }>(
        'SELECT target_id FROM mappings WHERE owner_id=$1 AND connection_id=$2 AND original_id=$3 AND connection_generation=$4',
        [g.ownerId, g.connectionId, bundleId, g.connectionGeneration],
      )
    ).rows[0];
    if (mapping) return mapping.target_id === bundleId;
    const api = await this.o.api(g);
    const exact = await api.findBundles(bundleId),
      wildcard = await api.findBundles('*');
    if (exact.length > 1 || wildcard.length > 1)
      throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    if (exact.length || wildcard.length) return true;
    const request = { identifier: bundleId, name: 'iSign ' + hash(bundleId).slice(0, 16) };
    const journal = new Provisioning(
      this.o.db,
      {
        find: async (kind) => {
          if (kind !== 'bundle') throw new Failure('PROVISIONING_KIND_REJECTED');
          return (await api.findBundles(bundleId)).map((resource) => ({ id: resource.id }));
        },
        create: async (kind) => {
          if (kind !== 'bundle') throw new Failure('PROVISIONING_KIND_REJECTED');
          return { id: (await api.bundle(bundleId, request.name)).id };
        },
      },
      () => this.now(),
    );
    try {
      await journal.ensure(g, 'bundle', request);
      return true;
    } catch (error) {
      if (error instanceof Failure && error.code === 'BUNDLE_IDENTIFIER_UNAVAILABLE') return false;
      throw error;
    }
  }
  readonly provision: PipelineProvisioner = async (input) => {
    const { grant: g, analysis, targets, signal } = input;
    const guard = async () => {
      if (signal.aborted) throw new Failure('EXECUTOR_CANCELLED', 409);
      return this.current(g);
    };
    const device = await guard();
    const mains = analysis.components.filter((c) => c.kind === 'app');
    if (
      mains.length !== 1 ||
      mains[0].bundleId !== analysis.bundleId ||
      Object.keys(targets).length !==
        analysis.components.filter((c) => c.kind !== 'framework' && c.kind !== 'dylib').length
    )
      throw new Failure('MAPPING_GRAPH_MISMATCH');
    const durable = await this.o.db.query<{
      target_id: string;
    }>(
      'SELECT target_id FROM mappings WHERE owner_id=$1 AND connection_id=$2 AND original_id=$3 AND connection_generation=$4',
      [g.ownerId, g.connectionId, analysis.bundleId, g.connectionGeneration],
    );
    if (durable.rows[0]?.target_id !== targets[analysis.bundleId])
      throw new Failure('MAPPING_GRAPH_MISMATCH', 409);
    for (const c of analysis.components.filter((c) => c.kind === 'appex'))
      if (
        !c.bundleId.startsWith(analysis.bundleId + '.') ||
        targets[c.bundleId] !==
          durable.rows[0].target_id + c.bundleId.slice(analysis.bundleId.length)
      )
        throw new Failure('MAPPING_GRAPH_MISMATCH');
    const record = await this.o.db.query<{
      identity: BootstrapIdentity;
      certificate: Certificate;
    }>(
      "SELECT identity,certificate FROM bootstrap_operations WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND certificate_state='committed'",
      [g.connectionOwnerId, g.connectionId, g.connectionGeneration],
    );
    const bootstrap = record.rows[0];
    if (!bootstrap?.identity?.secretRef || !bootstrap.certificate?.pem)
      throw new Failure('DISTRIBUTION_IDENTITY_REQUIRED', 409);
    let certificate: X509Certificate;
    try {
      certificate = new X509Certificate(bootstrap.certificate.pem);
    } catch {
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    }
    const spki = createHash('sha256')
        .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
        .digest('hex'),
      certificateDigest = createHash('sha256').update(certificate.raw).digest('hex'),
      fingerprint = certificate.fingerprint.replaceAll(':', '').toUpperCase();
    if (
      spki !== bootstrap.identity.spkiSha256 ||
      certificateTeamId(certificate.toString(), this.now()) !== device.team_id ||
      Date.parse(certificate.validTo) !== bootstrap.certificate.expiresAt
    )
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    const api = await this.o.api(g);
    const currentCerts = await api.findCertificates(spki);
    await guard();
    if (
      currentCerts.length !== 1 ||
      currentCerts[0].id !== bootstrap.certificate.id ||
      new X509Certificate(currentCerts[0].certificate).fingerprint256 !== certificate.fingerprint256
    )
      throw new Failure('CERTIFICATE_NOT_CURRENT', 409);
    const appleDevice = await api.rawDevice(device.udid, device.apple_resource_id);
    await guard();
    if (!appleDevice || appleDevice.status !== 'ENABLED')
      throw new Failure('DEVICE_NOT_READY', 409);
    const requests = new Map<
        string,
        {
          kind: 'bundle' | 'profile';
          request: Record<string, unknown>;
        }
      >(),
      resourceCache = new Map<string, ControlResource>();
    const journal = new Provisioning(
      this.o.db,
      {
        create: async (kind, request) => {
          if (kind === 'bundle') {
            const r = await api.bundle(String(request.identifier), String(request.name));
            resourceCache.set(r.id, r);
            return { id: r.id };
          }
          if (kind === 'profile') {
            const prior = await api.findProfiles(String(request.bundleId), String(request.name));
            await guard();
            if (prior.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
            if (prior[0]) {
              resourceCache.set(prior[0].id, prior[0]);
              return { id: prior[0].id };
            }
            const r = await api.profile(
              request as {
                name: string;
                bundleId: string;
                certificateIds: string[];
                deviceIds: string[];
              },
            );
            resourceCache.set(r.id, r);
            return { id: r.id };
          }
          throw new Failure('PROVISIONING_KIND_REJECTED');
        },
        find: async (kind, fingerprint) => {
          const saved = requests.get(fingerprint);
          if (!saved || kind !== saved.kind) throw new Failure('PROVISIONING_REQUEST_MISMATCH');
          const r = saved.request;
          const rows =
            kind === 'bundle'
              ? await api.findBundles(String(r.identifier))
              : await api.findProfiles(String(r.bundleId), String(r.name));
          for (const row of rows) resourceCache.set(row.id, row);
          return rows.map((row) => ({ id: row.id }));
        },
      },
      () => this.now(),
    );
    const ensure = async (kind: 'bundle' | 'profile', request: Record<string, unknown>) => {
      requests.set(hash(JSON.stringify(request)), { kind, request });
      await guard();
      const result = await journal.ensure(g, kind, request);
      await guard();
      return result.id;
    };
    const profilePayloads: {
      bundleId: string;
      cmsBase64: string;
      cmsSha256: string;
      resourceId: string;
    }[] = [];
    const seen = new Set<string>();
    const scopeBundles = new Map<string, ControlResource>();
    const scopeProfiles = new Map<string, Omit<(typeof profilePayloads)[number], 'bundleId'>>();
    for (const component of analysis.components.filter(
      (c) => c.kind !== 'framework' && c.kind !== 'dylib',
    )) {
      const target = targets[component.bundleId];
      if (!target || seen.has(target)) throw new Failure('MAPPING_GRAPH_MISMATCH');
      seen.add(target);
      if (!/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(target))
        throw new Failure('INVALID_BUNDLE_ID');
      const exact = await api.findBundles(target);
      await guard();
      if (exact.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
      const scope = exact.length ? target : '*';
      let bundle: ControlResource | undefined = exact[0] ?? scopeBundles.get(scope);
      if (!bundle) {
        const wildcard = await api.findBundles(scope);
        await guard();
        if (wildcard.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
        bundle = wildcard[0];
        if (!bundle) {
          const bundleRequest = { identifier: scope, name: 'iSign ' + hash(scope).slice(0, 16) };
          const resourceId = await ensure('bundle', bundleRequest);
          bundle = resourceCache.get(resourceId);
          if (!bundle) bundle = (await api.findBundles(scope)).find((row) => row.id === resourceId);
          await guard();
        }
      }
      if (!bundle || bundle.attributes.identifier !== scope)
        throw new Failure('BUNDLE_OWNERSHIP_PROOF_INVALID', 403);
      scopeBundles.set(scope, bundle);
      const bundleId = bundle.id;
      const reused = scopeProfiles.get(scope);
      if (reused) {
        profilePayloads.push({ bundleId: target, ...reused });
        continue;
      }
      const profileBase =
        'iSign-' +
        hash(
          canonicalReport({
            owner: g.ownerId,
            connection: g.connectionId,
            generation: g.connectionGeneration,
            target: scope,
            certificate: bootstrap.certificate.id,
            device: device.apple_resource_id,
          }),
        ).slice(0, 32);
      const profileName = await new ProfileRenewal({
        db: this.o.db,
        now: () => this.now(),
      }).chooseName(g, profileBase, bundleId, (bid, name) => api.findProfiles(bid, name), guard);
      const profileRequest = {
        name: profileName,
        bundleId,
        certificateIds: [bootstrap.certificate.id],
        deviceIds: [device.apple_resource_id],
      };
      const profileId = await ensure('profile', profileRequest);
      let profile = resourceCache.get(profileId);
      if (!profile)
        profile = (await api.findProfiles(bundleId, profileName)).find(
          (row) => row.id === profileId,
        );
      await guard();
      if (
        !profile ||
        profile.attributes.profileType !== 'IOS_APP_ADHOC' ||
        profile.attributes.profileState !== 'ACTIVE' ||
        typeof profile.attributes.profileContent !== 'string'
      )
        throw new Failure('PROFILE_NOT_READY', 409);
      const cms = Buffer.from(profile.attributes.profileContent, 'base64');
      if (!cms.length || cms.length > 65536) throw new Failure('PROFILE_CMS_INVALID', 409);
      const selected = {
        cmsBase64: cms.toString('base64'),
        cmsSha256: createHash('sha256').update(cms).digest('hex'),
        resourceId: profileId,
      };
      scopeProfiles.set(scope, selected);
      profilePayloads.push({ bundleId: target, ...selected });
    }
    const issued = await this.o.vault.prepareJobMaterial(g, bootstrap.identity.secretRef);
    let material: Awaited<ReturnType<PipelineProvisioner>>;
    try {
      await guard();
      if (issued.dataKey.length !== 32) throw new Failure('KMS_KEY_INVALID', 503);
      material = await this.o.rpc.call('material-prepare', g, {
        sealedKey: { envelope: issued.envelope, dataKey: issued.dataKey.toString('base64') },
        certificatePem: certificate.toString(),
        profiles: profilePayloads,
        expected: {
          ownerId: g.ownerId,
          teamId: device.team_id,
          certificateSha256: certificateDigest,
          fingerprint,
          udid: normalizeUdid(device.udid),
          deviceOs: device.os_version ?? null,
        },
      });
    } finally {
      issued.dataKey.fill(0);
    }
    await guard();
    if (
      material.identity.ownerId !== g.ownerId ||
      material.identity.teamId !== device.team_id ||
      material.identity.fingerprint !== fingerprint ||
      material.identity.expiresAt !== Date.parse(certificate.validTo) ||
      material.identity.materialPath !== 'materials/key.p12' ||
      normalizeUdid(material.udid) !== normalizeUdid(device.udid) ||
      (material.deviceOs ?? null) !== (device.os_version ?? null) ||
      Object.keys(material.profiles).length !== profilePayloads.length
    )
      throw new Failure('MATERIAL_BINDING_MISMATCH', 403);
    for (const p of profilePayloads) {
      const actual = material.profiles[p.bundleId] as
        | ((typeof material.profiles)[string] & {
            cmsSha256?: string;
            certificateSha256?: string;
          })
        | undefined;
      if (
        !actual ||
        actual.cmsSha256 !== p.cmsSha256 ||
        actual.certificateSha256 !== certificateDigest ||
        actual.bundleId !== p.bundleId ||
        !/^materials\/profile_[a-f0-9]{32}\.mobileprovision$/.test(actual.materialPath)
      )
        throw new Failure('PROFILE_MATERIAL_MISMATCH', 403);
    }
    createExecutorTask({
      ...material,
      ownerId: g.ownerId,
      components: analysis.components,
      targets,

      now: this.now(),
    });
    const identityId = hash(
      canonicalReport({
        owner: g.connectionOwnerId,
        connection: g.connectionId,
        generation: g.connectionGeneration,
        spki,
      }),
    );
    await this.o.db.transaction(async (tx) => {
      await tx.query('SELECT pg_advisory_xact_lock(736490)');
      await tx.query('SELECT id FROM connections WHERE id=$1 FOR UPDATE', [g.connectionId]);
      const active = await tx.query(
        "SELECT j.id FROM signing_jobs j JOIN apple_connections c ON c.id=j.connection_id AND c.owner_id=j.owner_id JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id JOIN users u ON u.id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$3 AND j.lease_expires>$4 AND c.id=$5 AND c.generation=$6 AND j.connection_generation=c.generation AND c.state='ready' AND d.id=$7 AND d.status='ready' AND d.connection_generation=c.generation AND u.deleted_at IS NULL FOR UPDATE OF u",
        [
          g.jobId,
          g.ownerId,
          g.leaseToken,
          this.now(),
          g.connectionId,
          g.connectionGeneration,
          g.deviceId,
        ],
      );
      if (!active.rows.length) throw new Failure('STALE_EXECUTOR_LEASE', 409);
      await tx.query(
        'INSERT INTO identities(id,owner_id,connection_id,secret_ref,certificate_digest,expires_at) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO UPDATE SET expires_at=$6',
        [
          identityId,
          g.connectionOwnerId,
          g.connectionId,
          bootstrap.identity.secretRef,
          certificateDigest,
          material.identity.expiresAt,
        ],
      );
      for (const p of profilePayloads) {
        const profile = material.profiles[p.bundleId],
          profileId = hash(
            canonicalReport({ identityId, bundle: p.bundleId, digest: p.cmsSha256 }),
          );
        await tx.query(
          'INSERT INTO profiles(id,owner_id,connection_id,identity_id,bundle_id,expires_at,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(id) DO UPDATE SET expires_at=$6,metadata=$7',
          [
            profileId,
            g.connectionOwnerId,
            g.connectionId,
            identityId,
            p.bundleId,
            profile.expiresAt,
            JSON.stringify({
              ...profile,
              generation: g.connectionGeneration,
              cmsSha256: p.cmsSha256,
              resourceId: p.resourceId,
              certificateDigest,
              deviceId: g.deviceId,
            }),
          ],
        );
      }
    });
    return material;
  };
}
