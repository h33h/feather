import { lockPrincipalConnections } from './access';
import { createPrivateKey, X509Certificate } from 'node:crypto';
import { Failure } from '../shared/index';
export function suggestedKeyId(filename: string) {
  return /^AuthKey_([A-Z0-9]{10})\.p8$/.exec(filename)?.[1] ?? null;
}
export function parseTeamKey(input: {
  filename: string;
  keyId?: string;
  issuerId: string;
  keyType?: string;
  p8: Buffer;
}) {
  if (input.keyType && input.keyType !== 'team') throw new Failure('TEAM_KEY_REQUIRED');
  const issuerId = input.issuerId.trim().toLowerCase();
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(issuerId))
    throw new Failure('INVALID_ISSUER_ID');
  const keyId = (input.keyId ?? suggestedKeyId(input.filename) ?? '').trim().toUpperCase();
  if (!/^[A-Z0-9]{10}$/.test(keyId)) throw new Failure('INVALID_KEY_ID');
  if (
    input.p8.length > 16384 ||
    !input.p8.toString('ascii').startsWith('-----BEGIN PRIVATE KEY-----')
  )
    throw new Failure('INVALID_P8');
  try {
    const key = createPrivateKey(input.p8);
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
      throw Error();
    return { issuerId, keyId, key };
  } catch {
    throw new Failure('INVALID_P8');
  }
}
export function certificateTeamId(pem: string, now: number) {
  try {
    const cert = new X509Certificate(pem);
    if (Date.parse(cert.validTo) <= now || Date.parse(cert.validFrom) > now) throw Error();
    const matches = cert.subject.split('\n').filter((x) => x.startsWith('OU='));
    if (matches.length !== 1 || !/^OU=[A-Z0-9]{10}$/.test(matches[0])) throw Error();
    return matches[0].slice(3);
  } catch {
    throw new Failure('TEAM_PROOF_REQUIRED', 409);
  }
}
export interface OnboardingPort {
  begin(owner: string): Promise<{
    id: string;
    generation: number;
  }>;
  seal(owner: string, connection: string, generation: number, p8: Buffer): Promise<string>;
  stageCredentials(
    owner: string,
    connection: string,
    generation: number,
    value: {
      issuerId: string;
      keyId: string;
      secretRef: string;
    },
  ): Promise<boolean>;
  commit(
    owner: string,
    connection: string,
    generation: number,
    value: {
      issuerId: string;
      keyId: string;
      teamId: string;
      secretRef: string;
    },
  ): Promise<boolean>;
  discard(owner: string, secretRef: string): Promise<void>;
  actionRequired(
    owner: string,
    connection: string,
    generation: number,
    reason: string,
  ): Promise<void>;
}
export interface TeamProof {
  teamId: string;
  teamName?: string;
  source: 'apple-api-certificate' | 'apple-api-profile';
  verified: boolean;
}
export class AppleOnboarding {
  constructor(
    private port: OnboardingPort,
    private validate: (
      key: ReturnType<typeof parseTeamKey>,
      binding: {
        ownerId: string;
        connectionId: string;
        generation: number;
      },
    ) => Promise<TeamProof>,
    private now: () => number,
  ) {}
  async connect(owner: string, input: Parameters<typeof parseTeamKey>[0]) {
    let connection:
      | {
          id: string;
          generation: number;
        }
      | undefined;
    let secretRef: string | undefined;
    try {
      const parsed = parseTeamKey(input);
      connection = await this.port.begin(owner);
      secretRef = await this.port.seal(owner, connection.id, connection.generation, input.p8);
      if (
        !(await this.port.stageCredentials(owner, connection.id, connection.generation, {
          issuerId: parsed.issuerId,
          keyId: parsed.keyId,
          secretRef,
        }))
      )
        throw new Failure('CONNECTION_CHANGED', 409);
      const proof = await this.validate(parsed, {
        ownerId: owner,
        connectionId: connection.id,
        generation: connection.generation,
      });
      if (
        !proof.verified ||
        !['apple-api-certificate', 'apple-api-profile'].includes(proof.source) ||
        !/^[A-Z0-9]{10}$/.test(proof.teamId)
      )
        throw new Failure('TEAM_PROOF_REQUIRED', 409);
      if (
        !(await this.port.commit(owner, connection.id, connection.generation, {
          issuerId: parsed.issuerId,
          keyId: parsed.keyId,
          teamId: proof.teamId,
          secretRef,
        }))
      )
        throw new Failure('CONNECTION_CHANGED', 409);
      return {
        id: connection.id,
        generation: connection.generation,
        state: 'ready',
        teamId: proof.teamId,
        teamName: proof.teamName ?? null,
        keyId: '••••••' + parsed.keyId.slice(-4),
        checkedAt: this.now(),
      };
    } catch (error) {
      const retain =
        error instanceof Failure &&
        ['TEAM_PROOF_REQUIRED', 'CERTIFICATE_REQUIRED'].includes(error.code);
      if (secretRef && !retain) {
        try {
          await this.port.discard(owner, secretRef);
        } catch {
          /* Durable deletion outbox retains cleanup after KMS failure. */
        }
      }
      if (connection)
        await this.port.actionRequired(
          owner,
          connection.id,
          connection.generation,
          error instanceof Failure ? error.code : 'APPLE_VALIDATION_UNAVAILABLE',
        );
      throw error;
    } finally {
      input.p8.fill(0);
    }
  }
}
import type { Database } from '../shared/database';
import type { Vault } from './vault';
import { id } from '../shared/index';
export class DatabaseOnboardingPort implements OnboardingPort {
  constructor(
    private db: Database,
    private vault: Vault,
    private now: () => number = Date.now,
  ) {}
  async begin(owner: string) {
    return this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, owner);
      if (
        !(
          await tx.query(
            'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
            [owner],
          )
        ).rows.length
      )
        throw new Failure('USER_UNAVAILABLE', 404);
      if (
        (
          await tx.query('SELECT user_id FROM user_apple_bindings WHERE user_id=$1 FOR UPDATE', [
            owner,
          ])
        ).rows.length
      )
        throw new Failure('APPLE_CONNECTION_EXISTS', 409);
      const old = (
        await tx.query<{ id: string; generation: number }>(
          'SELECT id,generation FROM connections WHERE owner_id=$1 FOR UPDATE',
          [owner],
        )
      ).rows[0];
      const connection = old?.id ?? id();
      const generation = (old?.generation ?? 0) + 1;
      if (old)
        await tx.query(
          "UPDATE connections SET generation=$2,state='validating',secret_ref=NULL,issuer_id=NULL,key_id=NULL,last_error=NULL,team_id='pending:'||id WHERE id=$1",
          [connection, generation],
        );
      else
        await tx.query(
          "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES($1,$2,$3,'validating','asc')",
          [connection, owner, 'pending:' + connection],
        );
      await tx.query(
        'INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES($1,$2,$1)',
        [owner, connection],
      );
      return { id: connection, generation };
    });
  }
  async seal(owner: string, connection: string, generation: number, p8: Buffer) {
    const current = await this.db.query(
      "SELECT id FROM connections WHERE id=$1 AND owner_id=$2 AND generation=$3 AND state='validating'",
      [connection, owner, generation],
    );
    if (!current.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
    return this.vault.seal(owner, connection, 'p8', p8);
  }
  async stageCredentials(
    owner: string,
    connection: string,
    generation: number,
    value: {
      issuerId: string;
      keyId: string;
      secretRef: string;
    },
  ) {
    const result = await this.db.query(
      "UPDATE connections SET issuer_id=$4,key_id=$5,secret_ref=$6 WHERE id=$1 AND owner_id=$2 AND generation=$3 AND state='validating' AND EXISTS(SELECT 1 FROM secrets WHERE id=$6 AND owner_id=$2 AND connection_id=$1 AND generation=$3 AND deleted_at IS NULL) AND EXISTS(SELECT 1 FROM users WHERE id=$2 AND deleted_at IS NULL) RETURNING id",
      [connection, owner, generation, value.issuerId, value.keyId, value.secretRef],
    );
    return result.rows.length === 1;
  }
  async commit(
    owner: string,
    connection: string,
    generation: number,
    value: {
      issuerId: string;
      keyId: string;
      teamId: string;
      secretRef: string;
    },
  ) {
    try {
      const result = await this.db.query(
        "UPDATE connections SET issuer_id=$4,key_id=$5,team_id=$6,secret_ref=$7,state='ready',last_error=NULL WHERE id=$1 AND owner_id=$2 AND generation=$3 AND (state='validating' OR (state='action_required' AND last_error IN('TEAM_PROOF_REQUIRED','CERTIFICATE_REQUIRED'))) AND EXISTS(SELECT 1 FROM users WHERE id=$2 AND deleted_at IS NULL) AND EXISTS(SELECT 1 FROM secrets WHERE id=$7 AND owner_id=$2 AND connection_id=$1 AND generation=$3 AND deleted_at IS NULL) RETURNING id",
        [connection, owner, generation, value.issuerId, value.keyId, value.teamId, value.secretRef],
      );
      return result.rows.length === 1;
    } catch (error) {
      if (
        (
          error as {
            code?: string;
          }
        ).code === '23505'
      )
        throw new Failure('TEAM_UNAVAILABLE', 409);
      throw error;
    }
  }
  async discard(owner: string, secretRef: string) {
    await this.db.transaction(async (tx) => {
      await tx.query('UPDATE secrets SET deleted_at=$3 WHERE id=$1 AND owner_id=$2', [
        secretRef,
        owner,
        this.now(),
      ]);
      await tx.query(
        'INSERT INTO secret_deletions(id,owner_id,secret_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(owner_id,secret_id) DO NOTHING',
        [id(), owner, secretRef, this.now()],
      );
      await tx.query('UPDATE connections SET secret_ref=NULL WHERE owner_id=$1 AND secret_ref=$2', [
        owner,
        secretRef,
      ]);
    });
    await this.vault.tombstone(owner, secretRef);
  }
  async actionRequired(owner: string, connection: string, generation: number, reason: string) {
    await this.db.query(
      "UPDATE connections SET state='action_required',last_error=$4 WHERE id=$1 AND owner_id=$2 AND generation=$3 AND state='validating'",
      [connection, owner, generation, reason],
    );
  }
}
export type BootstrapLease = {
  ownerId: string;
  connectionId: string;
  generation: number;
  nonce: string;
  expiresAt: number;
};
export type BootstrapIdentity = {
  secretRef: string;
  csr: string;
  spkiSha256: string;
};
export interface BootstrapPort {
  acquire(ownerId: string, connectionId: string, generation: number): Promise<BootstrapLease>;
  assertCurrent(lease: BootstrapLease): Promise<void>;
  /** Trusted VM generates the distribution key and persists ciphertext before returning public CSR. Never return the private key. */
  prepareIdentity(lease: BootstrapLease): Promise<BootstrapIdentity>;
  /** Durable, unique generation/SPKI operation claim: submitted/unknown must reconcile, never repeat POST. */
  claimCertificate(
    lease: BootstrapLease,
    identity: BootstrapIdentity,
  ): Promise<'new' | 'reconcile'>;
  findCertificates(
    lease: BootstrapLease,
    spkiSha256: string,
  ): Promise<
    {
      id: string;
      certificate: string;
    }[]
  >;
  createCertificate(
    lease: BootstrapLease,
    csr: string,
  ): Promise<{
    id: string;
    certificate: string;
  }>;
  markUnknown(lease: BootstrapLease, identity: BootstrapIdentity): Promise<void>;
  commitIdentity(
    lease: BootstrapLease,
    identity: BootstrapIdentity,
    certificate: {
      id: string;
      pem: string;
      teamId: string;
      expiresAt: number;
    },
  ): Promise<boolean>;
}
import { createHash } from 'node:crypto';
/** No pre-existing certificate needed: authorised native distribution-key bootstrap yields public Team proof. */
export class TeamBootstrap {
  constructor(
    private port: BootstrapPort,
    private now: () => number,
  ) {}
  async prove(ownerId: string, connectionId: string, generation: number): Promise<TeamProof> {
    const lease = await this.port.acquire(ownerId, connectionId, generation);
    const guard = async () => {
      if (
        lease.ownerId !== ownerId ||
        lease.connectionId !== connectionId ||
        lease.generation !== generation ||
        !lease.nonce ||
        lease.expiresAt <= this.now()
      )
        throw new Failure('STALE_BOOTSTRAP_LEASE', 409);
      await this.port.assertCurrent(lease);
    };
    await guard();
    const identity = await this.port.prepareIdentity(lease);
    await guard();
    if (
      !identity.secretRef ||
      !/^[a-f0-9]{64}$/.test(identity.spkiSha256) ||
      identity.csr.length > 16384 ||
      !identity.csr.startsWith('-----BEGIN CERTIFICATE REQUEST-----\n')
    )
      throw new Failure('BOOTSTRAP_IDENTITY_INVALID');
    const state = await this.port.claimCertificate(lease, identity);
    await guard();
    let matches = await this.port.findCertificates(lease, identity.spkiSha256);
    await guard();
    if (matches.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
    if (!matches.length) {
      if (state === 'reconcile') throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      await guard();
      try {
        matches = [await this.port.createCertificate(lease, identity.csr)];
      } catch {
        await this.port.markUnknown(lease, identity);
        throw new Failure('RESOURCE_RECONCILIATION_REQUIRED', 409);
      }
    }
    await guard();
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(matches[0].certificate);
    } catch {
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    }
    const digest = createHash('sha256')
      .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    if (digest !== identity.spkiSha256) throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    const teamId = certificateTeamId(cert.toString(), this.now());
    await guard();
    if (
      !(await this.port.commitIdentity(lease, identity, {
        id: matches[0].id,
        pem: cert.toString(),
        teamId,
        expiresAt: Date.parse(cert.validTo),
      }))
    )
      throw new Failure('CONNECTION_CHANGED', 409);
    return { teamId, source: 'apple-api-certificate', verified: true };
  }
}
