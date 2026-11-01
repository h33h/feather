import { createHash, randomBytes, X509Certificate } from 'node:crypto';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure, id } from '../shared';
import { assertAppleAccess, resolveAppleAccess, type ResolvedAppleAccess } from '../apple/access';
import { lockAuthority } from '../apple/access-lifecycle';
import { certificateTeamId } from '../apple/onboarding';
import type { AppleProvisioningApi } from '../apple/provisioning-client';
import type { Vault } from '../apple/vault';
import type { ControlProfileVerifier } from '../devices/eligibility';
import type { SigningMaterial } from './signing-material';
import { assetFailure, ASSET_LEASE_MS } from './operation-errors';
import { FeatherProfileService, type FeatherProfileRequest } from './profile-service';
export type FeatherSigningApi = Pick<
  AppleProvisioningApi,
  | 'findCertificates'
  | 'certificate'
  | 'revokeCertificate'
  | 'rawDevice'
  | 'findBundles'
  | 'bundle'
  | 'findProfiles'
  | 'profile'
>;
export type FeatherSigningPorts = {
  api: (binding: ResolvedAppleAccess) => Promise<FeatherSigningApi>;
  material: SigningMaterial;
  vault: Pick<Vault, 'seal' | 'openForClientSigning' | 'tombstone'>;
  verify: ControlProfileVerifier;
  now?: () => number;
};
const RENEWAL_WINDOW_MS = 30 * 86400000;
export type FeatherSigningStatus = {
  state: 'missing' | 'reconciling' | 'ready' | 'action_required' | 'revoked';
  identityId?: string;
  connectionId: string;
  connectionGeneration: number;
  revision?: number;
  teamId: string;
  certificateSha256?: string;
  expiresAt?: number;
  reason?: string;
  renewal?: { identityId: string; state: 'reconciling' | 'action_required'; reason?: string };
};
export type FeatherSigningBundle = {
  identityId: string;
  connectionId: string;
  connectionGeneration: number;
  revision: number;
  teamId: string;
  certificateSha256: string;
  expiresAt: number;
  p12: string;
  password: string;
};
export type FeatherIdentity = {
  id: string;
  replacement_for: string | null;
  connection_id: string;
  owner_id: string;
  generation: number;
  revision: number;
  state: string;
  secret_ref: string | null;
  csr: string | null;
  spki_sha256: string | null;
  certificate_id: string | null;
  certificate_pem: string | null;
  certificate_sha256: string | null;
  expires_at: number | null;
  reason: string | null;
  lease_token: string | null;
  lease_until: number;
};
export class FeatherSigningAssets {
  readonly now: () => number;
  private profileService: FeatherProfileService;
  constructor(
    readonly db: Database,
    readonly ports: FeatherSigningPorts,
  ) {
    this.now = ports.now ?? Date.now;
    this.profileService = new FeatherProfileService(this);
  }
  async binding(ownerId: string): Promise<ResolvedAppleAccess> {
    const r = (
      await this.db.query<{ id: string; generation: number }>(
        "SELECT id,generation FROM apple_connections WHERE owner_id=$1 AND state='ready' AND provider='asc'",
        [ownerId],
      )
    ).rows;
    if (r.length !== 1) throw new Failure('APPLE_ACCESS_UNAVAILABLE', 403);
    return resolveAppleAccess(this.db, ownerId, r[0].id, r[0].generation);
  }
  async guard(b: ResolvedAppleAccess, db: QueryDatabase = this.db) {
    return assertAppleAccess(db, b);
  }
  private async row(
    b: ResolvedAppleAccess,
    db: QueryDatabase = this.db,
  ): Promise<FeatherIdentity | undefined> {
    return (
      await db.query<FeatherIdentity>(
        "SELECT * FROM feather_signing_identities WHERE connection_id=$1 AND generation=$2 AND replacement_for IS NULL AND state<>'retired'",
        [b.connectionId, b.generation],
      )
    ).rows[0];
  }
  private async candidate(b: ResolvedAppleAccess, db: QueryDatabase = this.db) {
    return (
      await db.query<FeatherIdentity>(
        "SELECT * FROM feather_signing_identities WHERE connection_id=$1 AND generation=$2 AND replacement_for IS NOT NULL AND state<>'retired'",
        [b.connectionId, b.generation],
      )
    ).rows[0] as FeatherIdentity | undefined;
  }
  private async createIdentity(
    tx: QueryDatabase,
    b: ResolvedAppleAccess,
    replacementFor: string | null,
  ) {
    return (
      await tx.query<FeatherIdentity>(
        "INSERT INTO feather_signing_identities(id,connection_id,owner_id,generation,revision,state,created_at,replacement_for) SELECT $1,$2,$3,$4,COALESCE(MAX(revision),0)+1,'pending',$5,$6 FROM feather_signing_identities WHERE connection_id=$2 RETURNING *",
        [id(), b.connectionId, b.connectionOwnerId, b.generation, this.now(), replacementFor],
      )
    ).rows[0];
  }
  private dto(b: ResolvedAppleAccess, r?: FeatherIdentity): FeatherSigningStatus {
    const base = {
      connectionId: b.connectionId,
      connectionGeneration: b.generation,
      teamId: b.teamId,
    };
    if (!r) return { ...base, state: 'missing' };
    return {
      ...base,
      identityId: r.id,
      revision: r.revision,
      state:
        r.state === 'ready' && Number(r.expires_at) > this.now()
          ? 'ready'
          : r.state === 'action_required'
            ? 'action_required'
            : r.state === 'revoked' || r.state === 'revoking'
              ? 'revoked'
              : 'reconciling',
      ...(r.certificate_sha256 ? { certificateSha256: r.certificate_sha256 } : {}),
      ...(r.expires_at ? { expiresAt: Number(r.expires_at) } : {}),
      ...(r.reason ? { reason: r.reason } : {}),
    };
  }
  async status(ownerId: string): Promise<FeatherSigningStatus> {
    const b = await this.binding(ownerId),
      r = await this.row(b),
      candidate = await this.candidate(b);
    await this.guard(b);
    if (r?.state === 'ready' && candidate) {
      if (Number(r.expires_at) <= this.now()) return this.dto(b, candidate);
      return {
        ...this.dto(b, r),
        renewal: {
          identityId: candidate.id,
          state: candidate.state === 'action_required' ? 'action_required' : 'reconciling',
          ...(candidate.reason ? { reason: candidate.reason } : {}),
        },
      };
    }
    return this.dto(b, r);
  }
  async ensure(ownerId: string, options: { retry?: boolean } = {}): Promise<FeatherSigningStatus> {
    await this.cleanup();
    return this.resume(ownerId, options.retry === true);
  }
  private async resume(ownerId: string, retry = false): Promise<FeatherSigningStatus> {
    const b = await this.binding(ownerId),
      lease = id();
    const row = await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.guard(b, tx);
      let r = await this.row(b, tx);
      if (retry && (b.connectionOwnerId !== ownerId || b.accessGrantId))
        throw new Failure('OWNER_REQUIRED', 403);
      if (
        retry &&
        r &&
        (r.state === 'revoked' ||
          (r.state === 'revoking' &&
            Number(r.expires_at) <= this.now() &&
            Number(r.lease_until) <= this.now()))
      ) {
        await tx.query("UPDATE feather_signing_identities SET state='retired' WHERE id=$1", [r.id]);
        r = undefined;
      }
      // Keep the current row live throughout preparation, including rejected or uncertain renewal.
      if (r?.state === 'ready' && Number(r.expires_at) <= this.now() + RENEWAL_WINDOW_MS)
        r = (await this.candidate(b, tx)) ?? (await this.createIdentity(tx, b, r.id));
      if (!r) r = await this.createIdentity(tx, b, null);
      if (
        retry &&
        r.state === 'action_required' &&
        r.reason &&
        assetFailure(new Failure(r.reason))
      ) {
        r = (
          await tx.query<FeatherIdentity>(
            "UPDATE feather_signing_identities SET state='pending',reason=NULL WHERE id=$1 RETURNING *",
            [r.id],
          )
        ).rows[0];
      }
      if (
        ['ready', 'action_required', 'revoked', 'revoking'].includes(r.state) ||
        Number(r.lease_until) > this.now()
      )
        return r;
      return (
        await tx.query<FeatherIdentity>(
          'UPDATE feather_signing_identities SET lease_token=$2,lease_until=$3 WHERE id=$1 RETURNING *',
          [r.id, lease, this.now() + ASSET_LEASE_MS],
        )
      ).rows[0];
    });
    if (row.lease_token !== lease) return this.status(ownerId);
    try {
      if (!row.secret_ref) {
        const generated = await this.ports.material.generate(b.teamId);
        let secretRef: string | undefined;
        try {
          await this.guard(b);
          const plaintext = Buffer.from(
            JSON.stringify({
              privateKey: generated.privateKey.toString('utf8'),
              password: randomBytes(32).toString('base64url'),
            }),
          );
          try {
            secretRef = await this.ports.vault.seal(
              b.connectionOwnerId,
              b.connectionId,
              'feather-signing-key',
              plaintext,
            );
          } finally {
            plaintext.fill(0);
          }
          await this.save(b, row, lease, 'secret_ref=$3,csr=$4,spki_sha256=$5', [
            secretRef,
            generated.csr,
            generated.spkiSha256,
          ]);
          row.secret_ref = secretRef;
          row.csr = generated.csr;
          row.spki_sha256 = generated.spkiSha256;
        } catch (error) {
          if (secretRef) await this.ports.vault.tombstone(b.connectionOwnerId, secretRef);
          throw error;
        } finally {
          generated.privateKey.fill(0);
        }
      }
      const api = await this.ports.api(b);
      await this.guard(b);
      const matches = await api.findCertificates(row.spki_sha256!);
      await this.guard(b);
      if (matches.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
      let certificate = matches[0];
      if (!certificate && row.state === 'pending') {
        await this.save(b, row, lease, "state='submitted'", []);
        row.state = 'submitted';
        try {
          const result = await api.certificate(row.csr!, row.spki_sha256!);
          certificate = { id: result.resource.id, certificate: result.certificate };
        } catch (error) {
          await this.guard(b);
          const reason = assetFailure(error);
          await this.save(b, row, lease, 'state=$3,reason=$4', [
            reason ? 'action_required' : 'unknown',
            reason ?? 'CERTIFICATE_RECONCILIATION_REQUIRED',
          ]);
          return this.status(ownerId);
        }
      }
      if (certificate) {
        const cert = this.validateCertificate(b, row, certificate.certificate);
        await this.publish(b, row, lease, certificate.id, cert);
      }
      await this.guard(b);
      return this.status(ownerId);
    } finally {
      await this.db.query(
        'UPDATE feather_signing_identities SET lease_token=NULL,lease_until=0 WHERE id=$1 AND lease_token=$2',
        [row.id, lease],
      );
    }
  }
  private async publish(
    b: ResolvedAppleAccess,
    row: FeatherIdentity,
    lease: string,
    certificateId: string,
    cert: X509Certificate,
  ) {
    await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.guard(b, tx);
      const live = (
        await tx.query<FeatherIdentity>(
          "SELECT * FROM feather_signing_identities WHERE id=$1 AND lease_token=$2 AND lease_until>$3 AND state IN('pending','submitted','unknown') FOR UPDATE",
          [row.id, lease, this.now()],
        )
      ).rows[0];
      if (!live) throw new Failure('SIGNING_OPERATION_CHANGED', 409);
      if (live.replacement_for) {
        const current = await this.row(b, tx);
        if (!current || current.id !== live.replacement_for || current.state !== 'ready')
          throw new Failure('SIGNING_OPERATION_CHANGED', 409);
        await tx.query(
          "UPDATE feather_signing_identities SET state='retired',lease_token=NULL,lease_until=0 WHERE id=$1",
          [current.id],
        );
      }
      await tx.query(
        "UPDATE feather_signing_identities SET state='ready',replacement_for=NULL,certificate_id=$3,certificate_pem=$4,certificate_sha256=$5,expires_at=$6,reason=NULL WHERE id=$1 AND lease_token=$2",
        [
          row.id,
          lease,
          certificateId,
          cert.toString(),
          createHash('sha256').update(cert.raw).digest('hex'),
          Date.parse(cert.validTo),
        ],
      );
    });
  }
  private async save(
    b: ResolvedAppleAccess,
    r: FeatherIdentity,
    lease: string,
    set: string,
    values: unknown[],
  ) {
    await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.guard(b, tx);
      const changed = await tx.query(
        `UPDATE feather_signing_identities i SET ${set},lease_until=${this.now() + ASSET_LEASE_MS} WHERE id=$1 AND lease_token=$2 AND lease_until>${this.now()} AND state NOT IN('retired','revoking','revoked') AND (replacement_for IS NULL OR EXISTS(SELECT 1 FROM feather_signing_identities parent WHERE parent.id=i.replacement_for AND parent.state='ready' AND parent.replacement_for IS NULL)) RETURNING id`,
        [r.id, lease, ...values],
      );
      if (!changed.rows.length) throw new Failure('SIGNING_OPERATION_CHANGED', 409);
    });
  }
  private validateCertificate(b: ResolvedAppleAccess, r: FeatherIdentity, pem: string) {
    try {
      const cert = new X509Certificate(pem);
      if (
        certificateTeamId(cert.toString(), this.now()) !== b.teamId ||
        createHash('sha256')
          .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
          .digest('hex') !== r.spki_sha256
      )
        throw Error();
      return cert;
    } catch {
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    }
  }
  async currentIdentity(b: ResolvedAppleAccess) {
    await this.guard(b);
    const r = await this.row(b);
    if (!r || r.state !== 'ready' || !r.certificate_pem || Number(r.expires_at) <= this.now())
      throw new Failure('SIGNING_IDENTITY_NOT_READY', 409);
    const cert = this.validateCertificate(b, r, r.certificate_pem);
    if (
      createHash('sha256').update(cert.raw).digest('hex') !== r.certificate_sha256 ||
      Date.parse(cert.validTo) !== Number(r.expires_at)
    )
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    const api = await this.ports.api(b),
      matches = await api.findCertificates(r.spki_sha256!);
    await this.guard(b);
    if (
      matches.length !== 1 ||
      matches[0].id !== r.certificate_id ||
      new X509Certificate(matches[0].certificate).fingerprint256 !== cert.fingerprint256
    )
      throw new Failure('CERTIFICATE_NOT_CURRENT', 409);
    await this.assertIdentity(b, r);
    return r;
  }
  async assertIdentity(b: ResolvedAppleAccess, r: FeatherIdentity) {
    await this.guard(b);
    const live = await this.row(b);
    if (
      !live ||
      live.id !== r.id ||
      live.state !== 'ready' ||
      Number(live.expires_at) <= this.now() ||
      live.certificate_sha256 !== r.certificate_sha256
    )
      throw new Failure('SIGNING_IDENTITY_CHANGED', 409);
  }
  async bundle(ownerId: string): Promise<FeatherSigningBundle> {
    const b = await this.binding(ownerId),
      r = await this.currentIdentity(b);
    const plain = await this.ports.vault.openForClientSigning(b, r.id);
    let privateKey: Buffer | undefined, p12: Buffer | undefined;
    try {
      const secret = JSON.parse(plain.toString()) as { privateKey: string; password: string };
      privateKey = Buffer.from(secret.privateKey);
      p12 = await this.ports.material.package(privateKey, r.certificate_pem!, secret.password);
      await this.assertIdentity(b, r);
      return {
        identityId: r.id,
        connectionId: b.connectionId,
        connectionGeneration: b.generation,
        revision: r.revision,
        teamId: b.teamId,
        certificateSha256: r.certificate_sha256!,
        expiresAt: Number(r.expires_at),
        p12: p12.toString('base64'),
        password: secret.password,
      };
    } finally {
      plain.fill(0);
      privateKey?.fill(0);
      p12?.fill(0);
    }
  }
  profiles(ownerId: string, request: FeatherProfileRequest, options: { retry?: boolean } = {}) {
    return this.profileService.profiles(ownerId, request, options);
  }
  profileStatus(ownerId: string, operationId: string) {
    return this.profileService.status(ownerId, operationId);
  }
  async maintain() {
    await this.cleanup();
    const pending = (
      await this.db.query<{ owner_id: string }>(
        "SELECT owner_id FROM feather_signing_identities i WHERE (state IN('pending','submitted','unknown') AND lease_until<=$1) OR (state='ready' AND replacement_for IS NULL AND expires_at<=$2 AND NOT EXISTS(SELECT 1 FROM feather_signing_identities candidate WHERE candidate.replacement_for=i.id AND candidate.state<>'retired' AND (candidate.state='action_required' OR candidate.lease_until>$1))) GROUP BY owner_id ORDER BY MIN(created_at) LIMIT 5",
        [this.now(), this.now() + RENEWAL_WINDOW_MS],
      )
    ).rows;
    for (const row of pending) {
      try {
        await this.resume(row.owner_id);
      } catch {
        /* Retain journal for later reconciliation. */
      }
    }
    const profiles = (
      await this.db.query<{ id: string; owner_id: string }>(
        "SELECT id,owner_id FROM feather_profile_operations WHERE state='pending' AND lease_until<=$1 ORDER BY created_at LIMIT 5",
        [this.now()],
      )
    ).rows;
    for (const row of profiles) {
      try {
        await this.profileService.status(row.owner_id, row.id);
      } catch {
        /* Authority and proof errors never publish a result. */
      }
    }
  }
  private async cleanup() {
    // Serialize lifecycle decisions with candidate creation/publication, without holding KMS work.
    const secrets = await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await tx.query(
        "UPDATE feather_signing_identities i SET state='retired',lease_token=NULL,lease_until=0 WHERE i.state<>'retired' AND ((i.expires_at IS NOT NULL AND i.expires_at<=$1 AND i.state NOT IN('revoked','revoking') AND NOT EXISTS(SELECT 1 FROM feather_signing_identities candidate WHERE candidate.replacement_for=i.id AND candidate.state<>'retired')) OR NOT EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=i.connection_id AND c.owner_id=i.owner_id AND c.generation=i.generation AND c.state='ready' AND u.deleted_at IS NULL AND u.blocked_at IS NULL))",
        [this.now()],
      );
      await tx.query(
        "UPDATE feather_profile_operations p SET state='retired',result=NULL,resources='{}'::jsonb WHERE state<>'retired' AND (NOT EXISTS(SELECT 1 FROM feather_signing_identities i WHERE i.id=p.identity_id AND i.state='ready') OR NOT EXISTS(SELECT 1 FROM apple_connections c WHERE c.owner_id=p.owner_id AND c.id=p.binding->>'connectionId' AND c.generation=(p.binding->>'generation')::integer AND c.state='ready' AND c.access_grant_id IS NOT DISTINCT FROM p.binding->>'accessGrantId' AND c.access_grant_generation IS NOT DISTINCT FROM (p.binding->>'accessGrantGeneration')::integer))",
      );
      return (
        await tx.query<{ id: string; owner_id: string }>(
          "SELECT s.id,s.owner_id FROM secrets s WHERE s.purpose='feather-signing-key' AND (s.deleted_at IS NULL OR s.ciphertext<>'') AND (EXISTS(SELECT 1 FROM feather_signing_identities i WHERE i.secret_ref=s.id AND i.state IN('retired','revoked')) OR (NOT EXISTS(SELECT 1 FROM feather_signing_identities i WHERE i.secret_ref=s.id) AND NOT EXISTS(SELECT 1 FROM feather_signing_identities i WHERE i.connection_id=s.connection_id AND i.generation=s.generation AND i.lease_until>$1)) OR NOT EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=s.connection_id AND c.owner_id=s.owner_id AND c.generation=s.generation AND c.state='ready' AND u.deleted_at IS NULL AND u.blocked_at IS NULL))",
          [this.now()],
        )
      ).rows;
    });
    for (const s of secrets) await this.ports.vault.tombstone(s.owner_id, s.id);
  }
  async revoke(ownerId: string) {
    const b = await this.binding(ownerId);
    if (b.connectionOwnerId !== ownerId || b.accessGrantId)
      throw new Failure('OWNER_REQUIRED', 403);
    const lease = id();
    const r = await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.guard(b, tx);
      const row = await this.row(b, tx);
      if (!row || !row.certificate_id) throw new Failure('SIGNING_IDENTITY_NOT_READY', 409);
      if (row.state === 'revoked') return row;
      await tx.query(
        "UPDATE feather_signing_identities SET state='retired',lease_token=NULL,lease_until=0 WHERE replacement_for=$1 AND state<>'retired'",
        [row.id],
      );
      if (Number(row.lease_until) > this.now()) throw new Failure('SIGNING_OPERATION_BUSY', 409);
      return (
        await tx.query<FeatherIdentity>(
          "UPDATE feather_signing_identities SET state='revoking',lease_token=$2,lease_until=$3 WHERE id=$1 RETURNING *",
          [row.id, lease, this.now() + ASSET_LEASE_MS],
        )
      ).rows[0];
    });
    if (r.state === 'revoked') return this.status(ownerId);
    try {
      const api = await this.ports.api(b);
      await this.guard(b);
      await api.revokeCertificate(r.certificate_id!);
      await this.guard(b);
      await this.db.query(
        "UPDATE feather_signing_identities SET state='revoked',lease_token=NULL,lease_until=0 WHERE id=$1 AND lease_token=$2",
        [r.id, lease],
      );
      if (r.secret_ref) await this.ports.vault.tombstone(b.connectionOwnerId, r.secret_ref);
      await this.cleanup();
      return this.status(ownerId);
    } finally {
      await this.db.query(
        'UPDATE feather_signing_identities SET lease_token=NULL,lease_until=0 WHERE id=$1 AND lease_token=$2',
        [r.id, lease],
      );
    }
  }
}
