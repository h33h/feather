import { assertAppleAccess, type AppleAccess } from '../apple/access';
import { createHash, X509Certificate } from 'node:crypto';
import type { Database } from '../shared/database';
import { Failure, hash, id } from '../shared/index';
import { normalizeUdid } from './onboarding';
import { certificateTeamId } from '../apple/onboarding';
import { ProfileRenewal } from '../apple/profile-renewal';
export type ControlProfileInput = {
  binding: AppleAccess;
  cms: Buffer;
  cmsSha256: string;
  expected: {
    udid: string;
    certificateSha256: string;
    teamId: string;
    bundleId: string;
  };
  now: number;
};
export type VerifiedControlProfile = {
  cmsSha256: string;
  teamId: string;
  bundleId: string;
  deviceUdids: string[];
  certificateSha256s: string[];
  expiresAt: number;
  profileType: 'ad-hoc';
  entitlements?: Record<string, unknown>;
};
/** Only an authenticated, attested guest CMS parser may implement this callback. Browser booleans are never accepted. */
export type ControlProfileVerifier = (
  input: ControlProfileInput,
) => Promise<VerifiedControlProfile>;
export const denyControlProfile: ControlProfileVerifier = async () => {
  throw new Failure('PROFILE_CMS_VERIFIER_UNAVAILABLE', 503);
};
export type ControlResource = {
  id: string;
  attributes: Record<string, unknown>;
  relationships?: Record<
    string,
    {
      data?:
        | {
            id: string;
            type: string;
          }
        | {
            id: string;
            type: string;
          }[];
    }
  >;
};
export interface DeviceEligibilityApi {
  rawDevice(
    udid: string,
    resourceId: string,
  ): Promise<{
    id: string;
    status: string;
  } | null>;
  findBundles(identifier: string): Promise<ControlResource[]>;
  bundle(identifier: string, name: string): Promise<ControlResource>;
  findProfiles(bundleResourceId: string, name: string): Promise<ControlResource[]>;
  profile(input: {
    name: string;
    bundleId: string;
    certificateIds: string[];
    deviceIds: string[];
  }): Promise<ControlResource>;
}
export type EligibilityApiFactory = (binding: AppleAccess) => Promise<DeviceEligibilityApi>;
export class DeviceEligibilityProbe {
  constructor(
    private db: Database,
    private now: () => number,
    private api: EligibilityApiFactory,
    private verify: ControlProfileVerifier = denyControlProfile,
  ) {}
  private async current(b: AppleAccess, udid: string) {
    await assertAppleAccess(this.db, b);
    const result = await this.db.query<{
      team_id: string;
      identity: {
        secretRef: string;
        spkiSha256: string;
      };
      certificate: {
        id: string;
        pem: string;
        teamId: string;
        expiresAt: number;
      };
    }>(
      "SELECT c.team_id,b.identity,b.certificate FROM apple_connections c JOIN users u ON u.id=c.owner_id LEFT JOIN bootstrap_operations b ON b.owner_id=c.connection_owner_id AND b.connection_id=c.id AND b.generation=c.generation AND b.certificate_state='committed' WHERE c.id=$1 AND c.owner_id=$2 AND c.generation=$3 AND c.state='ready' AND c.provider='asc' AND u.deleted_at IS NULL AND EXISTS(SELECT 1 FROM devices d WHERE d.owner_id=$2 AND d.connection_id=$1 AND d.connection_generation=$3 AND d.udid_hash=$4 AND d.status!='locally_removed' AND d.enrollment_verified_at IS NOT NULL AND d.connection_owner_id=c.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM c.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation)",
      [b.connectionId, b.ownerId, b.generation, hash(udid)],
    );
    const row = result.rows[0];
    if (!row) throw new Failure('CONNECTION_CHANGED', 409);
    if (!row.certificate?.pem || !row.identity?.secretRef)
      throw new Failure('CERTIFICATE_REQUIRED', 409);
    const secret = await this.db.query(
      "SELECT id FROM secrets WHERE id=$1 AND owner_id=$2 AND connection_id=$3 AND generation=$4 AND purpose='distribution-key' AND deleted_at IS NULL",
      [row.identity.secretRef, b.connectionOwnerId, b.connectionId, b.generation],
    );
    if (!secret.rows.length) throw new Failure('CERTIFICATE_REQUIRED', 409);
    return row;
  }
  private async ensure(
    b: AppleAccess,
    udid: string,
    kind: string,
    request: Record<string, unknown>,
    find: () => Promise<ControlResource[]>,
    create: () => Promise<ControlResource>,
  ) {
    const fingerprint = hash(JSON.stringify(request));
    const claim = await this.db.transaction(async (tx) => {
      await tx.query('SELECT id FROM connections WHERE id=$1 AND owner_id=$2 FOR UPDATE', [
        b.connectionId,
        b.connectionOwnerId,
      ]);
      const old = await tx.query<{
        id: string;
        state: string;
        resource_id: string | null;
      }>(
        'SELECT id,state,resource_id FROM provisioning_operations WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND kind=$4 AND fingerprint=$5',
        [b.connectionOwnerId, b.connectionId, b.generation, kind, fingerprint],
      );
      if (old.rows[0]) {
        if (old.rows[0].state === 'rejected') {
          await tx.query(
            "UPDATE provisioning_operations SET state='submitted' WHERE id=$1 AND state='rejected'",
            [old.rows[0].id],
          );
          return { ...old.rows[0], created: true };
        }
        return { ...old.rows[0], created: false };
      }
      const operation = id();
      await tx.query(
        "INSERT INTO provisioning_operations(id,owner_id,connection_id,generation,kind,fingerprint,state,created_at) VALUES($1,$2,$3,$4,$5,$6,'submitted',$7)",
        [
          operation,
          b.connectionOwnerId,
          b.connectionId,
          b.generation,
          kind,
          fingerprint,
          this.now(),
        ],
      );
      return { id: operation, state: 'submitted', resource_id: null, created: true };
    });
    await this.current(b, udid);
    const matches = await find();
    await this.current(b, udid);
    if (matches.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    let result = matches[0];
    if (claim.resource_id && result?.id !== claim.resource_id)
      throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
    if (!result) {
      if (!claim.created) throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      try {
        await this.current(b, udid);
        result = await create();
      } catch (error) {
        const certain =
          error instanceof Failure &&
          [
            'APPLE_OPERATION_REJECTED',
            'APPLE_ACCESS_ACTION_REQUIRED',
            'APPLE_RATE_LIMITED',
          ].includes(error.code);
        await this.db.query(
          "UPDATE provisioning_operations SET state=$2 WHERE id=$1 AND state='submitted'",
          [claim.id, certain ? 'rejected' : 'unknown'],
        );
        throw error instanceof Failure
          ? error
          : new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      }
    }
    await this.current(b, udid);
    await this.db.query(
      "UPDATE provisioning_operations SET state='complete',resource_id=$2 WHERE id=$1",
      [claim.id, result.id],
    );
    return result;
  }
  async check(
    binding: AppleAccess,
    appleResourceId: string,
    inputUdid: string,
  ): Promise<{
    eligible?: boolean;
    processing?: boolean;
    ineligible?: boolean;
  }> {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(appleResourceId))
      throw new Failure('INVALID_APPLE_DEVICE_RESOURCE');
    const udid = normalizeUdid(inputUdid),
      state = await this.current(binding, udid);
    let certificate: X509Certificate;
    try {
      certificate = new X509Certificate(state.certificate.pem);
    } catch {
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    }
    const teamId = certificateTeamId(certificate.toString(), this.now());
    if (
      teamId !== state.team_id ||
      teamId !== state.certificate.teamId ||
      createHash('sha256')
        .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
        .digest('hex') !== state.identity.spkiSha256
    )
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    const certificateSha256 = createHash('sha256').update(certificate.raw).digest('hex');
    const api = await this.api(binding);
    const appleDevice = await api.rawDevice(udid, appleResourceId);
    await this.current(binding, udid);
    if (!appleDevice || appleDevice.id !== appleResourceId)
      throw new Failure('APPLE_DEVICE_NOT_FOUND', 409);
    if (appleDevice.status === 'DISABLED') return { ineligible: true };
    if (appleDevice.status !== 'ENABLED') throw new Failure('APPLE_DEVICE_STATUS_UNKNOWN', 409);
    const identifier =
      'com.isignservice.control.t' + hash(teamId).slice(0, 12) + '.g' + binding.generation;
    const bundle = await this.ensure(
      binding,
      udid,
      'eligibility-bundle',
      { identifier },
      () => api.findBundles(identifier),
      () => api.bundle(identifier, 'iSign device eligibility'),
    );
    if (bundle.attributes.identifier !== identifier)
      throw new Failure('CONTROL_BUNDLE_MISMATCH', 409);
    const baseName =
      'isign-control-' + hash(JSON.stringify({ binding, udid, certificateSha256 })).slice(0, 24);
    const name = await new ProfileRenewal({ db: this.db, now: this.now }).chooseName(
      binding,
      baseName,
      bundle.id,
      (bundleId, name) => api.findProfiles(bundleId, name),
      () => this.current(binding, udid),
    );
    const request = {
      name,
      bundleId: bundle.id,
      certificateIds: [state.certificate.id],
      deviceIds: [appleResourceId],
    };
    const profile = await this.ensure(
      binding,
      udid,
      'eligibility-profile',
      request,
      () => api.findProfiles(bundle.id, name),
      () => api.profile(request),
    );
    if (profile.attributes.profileState === 'INVALID')
      throw new Failure('CONTROL_PROFILE_INVALID', 409);
    if (
      typeof profile.attributes.profileContent !== 'string' ||
      profile.attributes.profileContent.length > 131072
    )
      throw new Failure('CONTROL_PROFILE_INVALID', 409);
    const encoded = profile.attributes.profileContent;
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw new Failure('CONTROL_PROFILE_INVALID', 409);
    const cms = Buffer.from(encoded, 'base64');
    if (!cms.length || cms.length > 65536) throw new Failure('CONTROL_PROFILE_INVALID', 409);
    const digest = createHash('sha256').update(cms).digest('hex');
    const receipt = await this.verify({
      binding,
      cms,
      cmsSha256: digest,
      expected: { udid, certificateSha256, teamId, bundleId: identifier },
      now: this.now(),
    });
    await this.current(binding, udid);
    if (
      receipt.cmsSha256 !== digest ||
      receipt.teamId !== teamId ||
      receipt.bundleId !== identifier ||
      receipt.profileType !== 'ad-hoc' ||
      !Number.isSafeInteger(receipt.expiresAt) ||
      receipt.expiresAt <= this.now() ||
      !Array.isArray(receipt.deviceUdids) ||
      !receipt.deviceUdids.includes(udid) ||
      !Array.isArray(receipt.certificateSha256s) ||
      !receipt.certificateSha256s.includes(certificateSha256)
    )
      throw new Failure('CONTROL_PROFILE_PROOF_MISMATCH', 409);
    return { eligible: true };
  }
}
