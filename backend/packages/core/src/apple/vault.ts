import type { JobMaterialEnvelope } from '../shared/signing-contracts';
import { assertAppleAccess, type AppleAccess } from './access';
import type { ExecutorGrant } from '../shared/runner-contracts';
import { canonicalReport } from '../shared/canonical-json';
import {
  decodeBootstrapBase64,
  isTrustedBootstrapEnvelope,
  type VerifiedBootstrapEnvelope,
  type BootstrapSealPurpose,
} from './bootstrap-sealing';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { Database } from '../shared/database';
import type { BootstrapLease } from './onboarding';
import { Failure, id } from '../shared/index';
export const SECRET_PURPOSES = {
  p8: 'p8',
  distributionKey: 'distribution-key',
  featherSigningKey: 'feather-signing-key',
  catalogAuth: 'catalog-auth',
} as const;
type Purpose = (typeof SECRET_PURPOSES)[keyof typeof SECRET_PURPOSES];
type BootstrapPurpose = 'p8' | 'distribution-key';
export interface Kms {
  generate(context: string): Promise<{
    plaintext: Buffer;
    wrapped: string;
  }>;
  unwrap(wrapped: string, context: string): Promise<Buffer>;
  revoke?(wrapped: string, context: string): Promise<void>;
}
type Secret = {
  id: string;
  owner_id: string;
  connection_id: string;
  purpose: string;
  wrapped_key: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  generation: number;
};

type Encrypted = {
  id: string;
  wrapped: string;
  nonce: string;
  ciphertext: string;
  tag: string;
};
function context(owner: string, connection: string, purpose: string, secret: string) {
  return JSON.stringify({ owner, connection, purpose, secret });
}
const bootstrapFrom =
  'FROM bootstrap_operations b JOIN connections c ON c.id=b.connection_id AND c.owner_id=b.owner_id JOIN users u ON u.id=b.owner_id';
const bootstrapWhere =
  "b.owner_id=$1 AND b.connection_id=$2 AND b.generation=$3 AND b.nonce=$4 AND b.expires_at=$5 AND b.expires_at>$6 AND c.generation=b.generation AND c.state IN('validating','action_required') AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL";
const jobSql =
  "SELECT s.* FROM secrets s JOIN connections c ON c.id=s.connection_id AND c.owner_id=s.owner_id JOIN signing_jobs j ON j.connection_id=s.connection_id AND j.connection_owner_id=s.owner_id JOIN users u ON u.id=s.owner_id WHERE s.id=$1 AND j.owner_id=$2 AND j.id=$3 AND j.lease_token=$4 AND j.lease_expires>$5 AND j.state IN('analyzing','provisioning','signing','verifying') AND s.purpose<>'feather-signing-key' AND s.deleted_at IS NULL AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND c.state='ready' AND c.generation=s.generation";
export class Vault {
  constructor(
    private db: Database,
    private kms: Kms,
    private now: () => number,
  ) {}
  private unavailable() {
    return new Failure('SECRET_UNAVAILABLE', 404);
  }
  private leaseValues(lease: BootstrapLease) {
    if (
      !lease ||
      !lease.ownerId ||
      !lease.connectionId ||
      !lease.nonce ||
      lease.nonce.length > 128 ||
      !Number.isSafeInteger(lease.generation) ||
      lease.generation < 1 ||
      !Number.isSafeInteger(lease.expiresAt) ||
      lease.expiresAt <= this.now()
    )
      throw this.unavailable();
    return [
      lease.ownerId,
      lease.connectionId,
      lease.generation,
      lease.nonce,
      lease.expiresAt,
      this.now(),
    ];
  }
  private async encrypt(
    owner: string,
    connection: string,
    purpose: Purpose,
    plaintext: Buffer,
    persist: (encrypted: Encrypted) => Promise<void>,
  ) {
    const secretId = id();
    const binding = context(owner, connection, purpose, secretId);
    const dataKey = await this.kms.generate(binding);
    try {
      if (dataKey.plaintext.length !== 32) throw new Failure('KMS_KEY_INVALID');
      const nonce = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', dataKey.plaintext, nonce);
      cipher.setAAD(Buffer.from(binding));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      await persist({
        id: secretId,
        wrapped: dataKey.wrapped,
        nonce: nonce.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        tag: cipher.getAuthTag().toString('base64'),
      });
      return secretId;
    } finally {
      dataKey.plaintext.fill(0);
    }
  }
  /** Ready connection secrets; only p8 is additionally allowed during validating onboarding. */
  async seal(owner: string, connection: string, purpose: Purpose, plaintext: Buffer) {
    if (!Object.values(SECRET_PURPOSES).includes(purpose)) throw this.unavailable();
    const row = await this.db.query<{
      generation: number;
    }>(
      "SELECT c.generation FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$1 AND c.owner_id=$2 AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND (c.state='ready' OR (c.state='validating' AND $3='p8'))",
      [connection, owner, purpose],
    );
    if (!row.rows.length) throw this.unavailable();
    return this.encrypt(owner, connection, purpose, plaintext, async (secret) => {
      const inserted = await this.db.query(
        "INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag,generation) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$3 AND c.owner_id=$2 AND c.generation=$9 AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND (c.state='ready' OR (c.state='validating' AND $4='p8')) RETURNING id",
        [
          secret.id,
          owner,
          connection,
          purpose,
          secret.wrapped,
          secret.nonce,
          secret.ciphertext,
          secret.tag,
          row.rows[0].generation,
        ],
      );
      if (!inserted.rows.length) throw this.unavailable();
    });
  }
  /** Pending ASC bootstrap only; the live durable lease is checked again by the atomic insert. */
  async sealForBootstrap(lease: BootstrapLease, purpose: BootstrapPurpose, plaintext: Buffer) {
    if (purpose !== 'p8' && purpose !== 'distribution-key') throw this.unavailable();
    const values = this.leaseValues(lease);
    const current = await this.db.query(
      `SELECT b.nonce ${bootstrapFrom} WHERE ${bootstrapWhere}`,
      values,
    );
    if (!current.rows.length) throw this.unavailable();
    return this.encrypt(lease.ownerId, lease.connectionId, purpose, plaintext, async (secret) => {
      const live = this.leaseValues(lease);
      const inserted = await this.db.query(
        `INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag,generation) SELECT $7,$1,$2,$8,$9,$10,$11,$12,$3 ${bootstrapFrom} WHERE ${bootstrapWhere} RETURNING id`,
        [...live, secret.id, purpose, secret.wrapped, secret.nonce, secret.ciphertext, secret.tag],
      );
      if (!inserted.rows.length) throw this.unavailable();
    });
  }
  /** Issue an exact server-owned encryption context; caller wipes the returned data key after TLS guest delivery. */
  async prepareBootstrapEnvelope(
    lease: BootstrapLease,
    purpose: BootstrapSealPurpose,
    request: {
      grantNonce: string;
      audience: string;
      instanceId: string;
      expiresAt: number;
    },
  ) {
    if (
      (purpose !== 'p8' && purpose !== 'distribution-key') ||
      !/^[A-Za-z0-9_-]{32,128}$/.test(request.grantNonce) ||
      !/^[A-Za-z0-9:_-]{1,100}$/.test(request.audience) ||
      !/^[A-Za-z0-9_.:-]{1,128}$/.test(request.instanceId) ||
      !Number.isSafeInteger(request.expiresAt) ||
      request.expiresAt > lease.expiresAt ||
      request.expiresAt <= this.now() ||
      request.expiresAt > this.now() + 120000
    )
      throw this.unavailable();
    const live = this.leaseValues(lease);
    const current = await this.db.query(
      `SELECT b.nonce ${bootstrapFrom} WHERE ${bootstrapWhere}`,
      live,
    );
    if (!current.rows.length) throw this.unavailable();
    const secretId = id();
    const aad = context(lease.ownerId, lease.connectionId, purpose, secretId);
    const key = await this.kms.generate(aad);
    let delivered = false;
    try {
      if (key.plaintext.length !== 32 || !key.wrapped || key.wrapped.length > 16384)
        throw this.unavailable();
      const inserted = await this.db.query(
        `INSERT INTO bootstrap_secret_grants(secret_id,owner_id,connection_id,generation,bootstrap_nonce,bootstrap_expires_at,grant_nonce,audience,instance_id,purpose,expires_at,wrapped_key,aad) SELECT $7,$1,$2,$3,$4,$5,$8,$9,$10,$11,$12,$13,$14 ${bootstrapFrom} WHERE ${bootstrapWhere} AND $12>$6 AND $12<=$5 RETURNING secret_id`,
        [
          ...this.leaseValues(lease),
          secretId,
          request.grantNonce,
          request.audience,
          request.instanceId,
          purpose,
          request.expiresAt,
          key.wrapped,
          aad,
        ],
      );
      if (!inserted.rows.length) throw this.unavailable();
      delivered = true;
      return { secretId, wrappedKey: key.wrapped, aad, dataKey: key.plaintext };
    } finally {
      if (!delivered) key.plaintext.fill(0);
    }
  }
  /** Accept only process-authenticated guest ciphertext, never a JSON/browser persistence assertion. */
  async acceptBootstrapEnvelope(lease: BootstrapLease, envelope: VerifiedBootstrapEnvelope) {
    if (
      !isTrustedBootstrapEnvelope(envelope) ||
      (envelope.purpose !== 'p8' && envelope.purpose !== 'distribution-key') ||
      envelope.aad !==
        context(lease.ownerId, lease.connectionId, envelope.purpose, envelope.secretId) ||
      !Number.isSafeInteger(envelope.expiresAt) ||
      envelope.expiresAt <= this.now() ||
      envelope.expiresAt > lease.expiresAt
    )
      throw this.unavailable();
    decodeBootstrapBase64(envelope.nonce, 12, 12);
    decodeBootstrapBase64(envelope.tag, 16, 16);
    decodeBootstrapBase64(envelope.ciphertext, envelope.purpose === 'p8' ? 16384 : 65536);
    return this.db.transaction(async (tx) => {
      const values = [
        ...this.leaseValues(lease),
        envelope.secretId,
        envelope.grantNonce,
        envelope.audience,
        envelope.instanceId,
        envelope.purpose,
        envelope.expiresAt,
        envelope.wrappedKey,
        envelope.aad,
      ];
      const reservation = await tx.query(
        `SELECT g.secret_id FROM bootstrap_secret_grants g JOIN bootstrap_operations b ON b.owner_id=g.owner_id AND b.connection_id=g.connection_id AND b.generation=g.generation JOIN connections c ON c.id=b.connection_id AND c.owner_id=b.owner_id JOIN users u ON u.id=b.owner_id WHERE ${bootstrapWhere} AND g.secret_id=$7 AND g.grant_nonce=$8 AND g.audience=$9 AND g.instance_id=$10 AND g.purpose=$11 AND g.expires_at=$12 AND g.expires_at>$6 AND g.wrapped_key=$13 AND g.aad=$14 AND g.bootstrap_nonce=$4 AND g.bootstrap_expires_at=$5 AND g.consumed=false FOR UPDATE OF g,b,c,u`,
        values,
      );
      if (!reservation.rows.length) throw this.unavailable();
      await tx.query(
        'INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag,generation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [
          envelope.secretId,
          lease.ownerId,
          lease.connectionId,
          envelope.purpose,
          envelope.wrappedKey,
          envelope.nonce,
          envelope.ciphertext,
          envelope.tag,
          lease.generation,
        ],
      );
      const consumed = await tx.query(
        'UPDATE bootstrap_secret_grants SET consumed=true WHERE secret_id=$1 AND grant_nonce=$2 AND consumed=false RETURNING secret_id',
        [envelope.secretId, envelope.grantNonce],
      );
      if (!consumed.rows.length) throw this.unavailable();
      return envelope.secretId;
    });
  }
  private async decrypt(row: Secret, recheck: () => Promise<Secret | undefined>) {
    let key: Buffer | undefined;
    let plaintext: Buffer | undefined;
    let partial: Buffer | undefined;
    let final: Buffer | undefined;
    const guard = async () => {
      const live = await recheck();
      if (
        !live ||
        [
          'id',
          'owner_id',
          'connection_id',
          'purpose',
          'generation',
          'wrapped_key',
          'nonce',
          'ciphertext',
          'tag',
        ].some((field) => live[field as keyof Secret] !== row[field as keyof Secret])
      )
        throw this.unavailable();
    };
    try {
      key = await this.kms.unwrap(
        row.wrapped_key,
        context(row.owner_id, row.connection_id, row.purpose, row.id),
      );
      if (key.length !== 32) throw this.unavailable();
      await guard();
      const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(row.nonce, 'base64'));
      cipher.setAAD(Buffer.from(context(row.owner_id, row.connection_id, row.purpose, row.id)));
      cipher.setAuthTag(Buffer.from(row.tag, 'base64'));
      partial = cipher.update(Buffer.from(row.ciphertext, 'base64'));
      final = cipher.final();
      plaintext = Buffer.concat([partial, final]);
      partial.fill(0);
      final.fill(0);
      await guard();
      return plaintext;
    } catch {
      plaintext?.fill(0);
      throw this.unavailable();
    } finally {
      key?.fill(0);
      partial?.fill(0);
      final?.fill(0);
    }
  }
  /** Only the currently attached ASC p8 of an owner/current generation/ready connection. */
  async openForConnection(owner: string, connection: string, generation: number) {
    if (!Number.isSafeInteger(generation) || generation < 1) throw this.unavailable();
    const load = async () => {
      const rows = await this.db.query<Secret>(
        "SELECT s.* FROM connections c JOIN secrets s ON s.id=c.secret_ref AND s.owner_id=c.owner_id AND s.connection_id=c.id JOIN users u ON u.id=c.owner_id WHERE c.id=$1 AND c.owner_id=$2 AND c.generation=$3 AND s.generation=$3 AND c.state='ready' AND c.provider='asc' AND s.purpose='p8' AND s.deleted_at IS NULL AND u.deleted_at IS NULL AND u.blocked_at IS NULL",
        [connection, owner, generation],
      );
      return rows.rows[0];
    };
    const row = await load();
    if (!row) throw this.unavailable();
    return this.decrypt(row, load);
  }
  /** Exportable client keys are never reachable through bootstrap/job readers. */
  async openForClientSigning(binding: AppleAccess, identityId: string) {
    const load = async () => {
      const access = await assertAppleAccess(this.db, binding);
      const result = await this.db.query<Secret>(
        "SELECT s.* FROM feather_signing_identities i JOIN secrets s ON s.id=i.secret_ref AND s.owner_id=i.owner_id AND s.connection_id=i.connection_id AND s.generation=i.generation WHERE i.id=$1 AND i.owner_id=$2 AND i.connection_id=$3 AND i.generation=$4 AND i.state='ready' AND i.replacement_for IS NULL AND i.expires_at>$5 AND s.purpose='feather-signing-key' AND s.deleted_at IS NULL",
        [
          identityId,
          access.connectionOwnerId,
          binding.connectionId,
          binding.generation,
          this.now(),
        ],
      );
      return result.rows[0];
    };
    const row = await load();
    if (!row) throw this.unavailable();
    return this.decrypt(row, load);
  }
  /** Lease-scoped reads during pending bootstrap, never catalog credentials or another generation. */
  async openForBootstrap(lease: BootstrapLease, secretId: string, purpose?: BootstrapPurpose) {
    if (purpose !== undefined && purpose !== 'p8' && purpose !== 'distribution-key')
      throw this.unavailable();
    const load = async () => {
      const values = this.leaseValues(lease);
      const rows = await this.db.query<Secret>(
        `SELECT s.* ${bootstrapFrom} JOIN secrets s ON s.owner_id=b.owner_id AND s.connection_id=b.connection_id AND s.generation=b.generation WHERE ${bootstrapWhere} AND s.id=$7 AND s.purpose IN('p8','distribution-key') AND ($8::text IS NULL OR s.purpose=$8) AND s.deleted_at IS NULL`,
        [...values, secretId, purpose ?? null],
      );
      return rows.rows[0];
    };
    const row = await load();
    if (!row) throw this.unavailable();
    return this.decrypt(row, load);
  }
  /** Only unwrap the AES key; private material remains opaque ciphertext until trusted guest decryption. */
  async prepareJobMaterial(
    grant: ExecutorGrant,
    secretId: string,
  ): Promise<{
    envelope: JobMaterialEnvelope;
    dataKey: Buffer;
  }> {
    const binding = { ...grant };
    if (
      !binding.ownerId ||
      !binding.jobId ||
      !binding.connectionId ||
      !binding.deviceId ||
      !binding.leaseToken ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(binding.taskNonce) ||
      !/^[A-Za-z0-9_.:-]{1,128}$/.test(binding.isolationInstanceId) ||
      !Number.isSafeInteger(binding.connectionGeneration) ||
      binding.connectionGeneration < 1 ||
      !Number.isSafeInteger(binding.expiresAt) ||
      binding.expiresAt <= this.now() ||
      !/^[a-f0-9]{64}$/.test(binding.uploadDigest) ||
      (binding.planDigest !== undefined && !/^[a-f0-9]{64}$/.test(binding.planDigest))
    )
      throw this.unavailable();
    const load = async () => {
      if (binding.expiresAt <= this.now()) throw this.unavailable();
      const result = await this.db.query<
        Secret & {
          task_binding: ExecutorGrant;
        }
      >(
        "SELECT s.*,t.binding AS task_binding FROM secrets s JOIN connections c ON c.id=s.connection_id AND c.owner_id=s.owner_id JOIN users u ON u.id=s.owner_id JOIN signing_jobs j ON j.connection_id=s.connection_id AND j.connection_owner_id=s.owner_id JOIN uploads a ON a.id=j.upload_id AND a.owner_id=j.owner_id JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id AND d.connection_id=c.id JOIN executor_tasks t ON t.job_id=j.id AND t.owner_id=j.owner_id WHERE s.id=$1 AND j.owner_id=$2 AND j.id=$3 AND c.id=$4 AND c.generation=$5 AND s.generation=$5 AND j.connection_id=$4 AND j.connection_generation=$5 AND d.connection_generation=$5 AND j.lease_token=$6 AND j.lease_expires>$7 AND j.state IN('analyzing','provisioning','signing','verifying') AND d.id=$8 AND d.status='ready' AND t.nonce=$9 AND t.consumed=false AND t.expires_at>$7 AND t.expires_at=$11 AND a.digest=$10 AND a.expires_at>$7 AND c.state='ready' AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND s.deleted_at IS NULL AND s.purpose='distribution-key'",
        [
          secretId,
          binding.ownerId,
          binding.jobId,
          binding.connectionId,
          binding.connectionGeneration,
          binding.leaseToken,
          this.now(),
          binding.deviceId,
          binding.taskNonce,
          binding.uploadDigest,
          binding.expiresAt,
        ],
      );
      const row = result.rows[0];
      if (
        !row ||
        row.owner_id !== binding.connectionOwnerId ||
        canonicalReport(row.task_binding) !== canonicalReport(binding)
      )
        throw this.unavailable();
      return row;
    };
    const row = await load();
    try {
      decodeBootstrapBase64(row.nonce, 12, 12);
      decodeBootstrapBase64(row.tag, 16, 16);
      decodeBootstrapBase64(row.ciphertext, 65536);
    } catch {
      throw this.unavailable();
    }
    if (!row.wrapped_key || row.wrapped_key.length > 16384) throw this.unavailable();
    const aad = context(row.owner_id, row.connection_id, row.purpose, row.id);
    let key: Buffer | undefined;
    let delivered = false;
    try {
      key = await this.kms.unwrap(row.wrapped_key, aad);
      if (key.length !== 32) throw this.unavailable();
      const current = await load();
      if (
        [
          'id',
          'owner_id',
          'connection_id',
          'purpose',
          'generation',
          'wrapped_key',
          'nonce',
          'ciphertext',
          'tag',
        ].some((field) => current[field as keyof Secret] !== row[field as keyof Secret])
      )
        throw this.unavailable();
      delivered = true;
      return {
        envelope: {
          owner: row.owner_id,
          connection: row.connection_id,
          purpose: 'distribution-key',
          secret: row.id,
          aad,
          wrappedKey: row.wrapped_key,
          nonce: row.nonce,
          ciphertext: row.ciphertext,
          tag: row.tag,
          generation: row.generation,
        },
        dataKey: key,
      };
    } catch {
      throw this.unavailable();
    } finally {
      if (!delivered) key?.fill(0);
    }
  }
  async openForJob(owner: string, secretId: string, jobId: string, lease: string) {
    const load = async () => {
      const result = await this.db.query<Secret>(jobSql, [
        secretId,
        owner,
        jobId,
        lease,
        this.now(),
      ]);
      return result.rows[0];
    };
    const row = await load();
    if (!row) throw this.unavailable();
    return this.decrypt(row, load);
  }
  async tombstone(owner: string, secretId: string) {
    const row = await this.db.query<Secret>(
      'UPDATE secrets SET deleted_at=$3 WHERE id=$1 AND owner_id=$2 RETURNING *',
      [secretId, owner, this.now()],
    );
    if (!row.rows.length) throw this.unavailable();
    const secret = row.rows[0];
    if (!secret.wrapped_key && !secret.ciphertext) return;
    await this.kms.revoke?.(
      secret.wrapped_key,
      context(owner, secret.connection_id, secret.purpose, secret.id),
    );
    await this.db.query(
      "UPDATE secrets SET wrapped_key='',ciphertext='',nonce='',tag='' WHERE id=$1 AND owner_id=$2",
      [secretId, owner],
    );
  }
}
