import { createHash, createHmac, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import type { Vault } from './vault';
import type { BootstrapIdentity, BootstrapLease } from './onboarding';
import { Failure, token } from '../shared/index';
import { canonicalReport } from '../shared/canonical-json';
export type BootstrapSealPurpose = 'distribution-key' | 'p8';
export type BootstrapMaterialFormat = 'encrypted-pem-with-password-v1' | 'p8-pem-v1';
export type BootstrapSealingGrant = {
  version: 1;
  operation: 'bootstrap-seal';
  lease: BootstrapLease;
  secretId: string;
  grantNonce: string;
  audience: string;
  instanceId: string;
  purpose: BootstrapSealPurpose;
  materialFormat: BootstrapMaterialFormat;
  expiresAt: number;
  wrappedKey: string;
  aad: string;
  signature: string;
};
export type BootstrapCiphertextEnvelope = {
  secretId: string;
  grantNonce: string;
  audience: string;
  instanceId: string;
  purpose: BootstrapSealPurpose;
  expiresAt: number;
  wrappedKey: string;
  aad: string;
  nonce: string;
  ciphertext: string;
  tag: string;
};
export type BootstrapEnvelopeReceipt = {
  report: {
    version: 1;
    operation: 'bootstrap-envelope';
    grant: BootstrapSealingGrant;
    materialFormat: BootstrapMaterialFormat;
    envelope: BootstrapCiphertextEnvelope;
    csr: string;
    spkiSha256: string;
    ciphertextSha256: string;
  };
  attestation: string;
};
const trustedEnvelope = Symbol('trusted-bootstrap-envelope');
const authenticatedEnvelopes = new WeakSet<object>();
export type VerifiedBootstrapEnvelope = BootstrapCiphertextEnvelope & {
  readonly [trustedEnvelope]: true;
};
/** Process-local provenance cannot be manufactured by JSON/browser proof booleans. */
export function isTrustedBootstrapEnvelope(value: unknown): value is VerifiedBootstrapEnvelope {
  return !!value && typeof value === 'object' && authenticatedEnvelopes.has(value);
}
function mint(envelope: BootstrapCiphertextEnvelope) {
  const value = Object.freeze({ ...envelope, [trustedEnvelope]: true as const });
  authenticatedEnvelopes.add(value);
  return value;
}
function reject(): never {
  throw new Failure('BOOTSTRAP_ENVELOPE_INVALID', 403);
}
function exactKeys(value: unknown, keys: string[]) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(',') !== keys.sort().join(',')
  )
    reject();
}
export function decodeBootstrapBase64(value: unknown, max: number, exact?: number) {
  if (
    typeof value !== 'string' ||
    !value ||
    value.length > Math.ceil(max / 3) * 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  )
    reject();
  const decoded = Buffer.from(value, 'base64');
  if (
    decoded.length > max ||
    decoded.toString('base64') !== value ||
    (exact !== undefined && decoded.length !== exact)
  )
    reject();
  return decoded;
}
function authenticated(key: Buffer, domain: string, value: unknown, signature: unknown) {
  return (
    typeof signature === 'string' &&
    /^[a-f0-9]{64}$/.test(signature) &&
    timingSafeEqual(
      createHmac('sha256', key)
        .update(domain + '\0' + canonicalReport(value))
        .digest(),
      Buffer.from(signature, 'hex'),
    )
  );
}
type DerNode = {
  tag: number;
  start: number;
  content: number;
  end: number;
};
function derNode(buffer: Buffer, start: number): DerNode {
  if (start < 0 || start + 2 > buffer.length) reject();
  const tag = buffer[start],
    first = buffer[start + 1];
  let length = first,
    content = start + 2;
  if (first & 128) {
    const count = first & 127;
    if (count < 1 || count > 3 || content + count > buffer.length || buffer[content] === 0)
      reject();
    length = 0;
    for (let index = 0; index < count; index++) length = length * 256 + buffer[content + index];
    if (length < 128) reject();
    content += count;
  }
  if (content + length > buffer.length) reject();
  return { tag, start, content, end: content + length };
}
function derChildren(buffer: Buffer, node: DerNode) {
  const result: DerNode[] = [];
  for (let offset = node.content; offset < node.end;) {
    const child = derNode(buffer, offset);
    if (child.end > node.end || result.length >= 16) reject();
    result.push(child);
    offset = child.end;
  }
  return result;
}
/** Parse only bounded PKCS#10 public data and verify possession of the CSR's public key. */
export function bootstrapCsrSpki(csr: string) {
  if (
    typeof csr !== 'string' ||
    csr.length > 16384 ||
    !/^-----BEGIN CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE REQUEST-----\r?\n?$/.test(
      csr,
    )
  )
    reject();
  const encoded = csr.replace(
    /-----BEGIN CERTIFICATE REQUEST-----|-----END CERTIFICATE REQUEST-----|\s/g,
    '',
  );
  const der = decodeBootstrapBase64(encoded, 12000);
  const root = derNode(der, 0);
  if (root.tag !== 0x30 || root.end !== der.length) reject();
  const parts = derChildren(der, root);
  if (
    parts.length !== 3 ||
    parts[0].tag !== 0x30 ||
    parts[1].tag !== 0x30 ||
    parts[2].tag !== 3 ||
    der[parts[2].content] !== 0
  )
    reject();
  const info = derChildren(der, parts[0]);
  if (
    info.length < 3 ||
    info.length > 4 ||
    info[0].tag !== 2 ||
    der.subarray(info[0].start, info[0].end).toString('hex') !== '020100' ||
    info[1].tag !== 0x30 ||
    info[2].tag !== 0x30 ||
    (info[3] && info[3].tag !== 0xa0)
  )
    reject();
  const spki = der.subarray(info[2].start, info[2].end);
  let publicKey;
  try {
    publicKey = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  } catch {
    reject();
  }
  const algorithm = der.subarray(parts[1].content, parts[1].end).toString('hex');
  if (publicKey.asymmetricKeyType === 'rsa') {
    if (
      ![2048, 3072, 4096].includes(publicKey.asymmetricKeyDetails?.modulusLength ?? 0) ||
      !['06092a864886f70d01010b0500', '06092a864886f70d01010b'].includes(algorithm)
    )
      reject();
  } else if (publicKey.asymmetricKeyType === 'ec') {
    if (
      publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
      algorithm !== '06082a8648ce3d040302'
    )
      reject();
  } else reject();
  try {
    if (
      !verify(
        'sha256',
        der.subarray(parts[0].start, parts[0].end),
        publicKey,
        der.subarray(parts[2].content + 1, parts[2].end),
      )
    )
      reject();
  } catch {
    reject();
  }
  return {
    spkiSha256: createHash('sha256').update(spki).digest('hex'),
    keyType: publicKey.asymmetricKeyType,
  };
}
/** Server-only coordinator: data-key delivery is restricted to authenticated guest RPC over TLS. */
export class BootstrapSealing {
  #vault: Vault;
  #proofKey: Buffer;
  #audience: string;
  #now: () => number;
  constructor(options: { vault: Vault; proofKey: Buffer; audience: string; now?: () => number }) {
    if (options.proofKey.length < 32 || !/^[A-Za-z0-9:_-]{1,100}$/.test(options.audience))
      throw new Failure('BOOTSTRAP_SEALING_CONFIG_INVALID', 503);
    this.#vault = options.vault;
    this.#proofKey = Buffer.from(options.proofKey);
    this.#audience = options.audience;
    this.#now = options.now ?? Date.now;
  }
  async issue(
    lease: BootstrapLease,
    purpose: BootstrapSealPurpose,
    instanceId: string,
    maxExpiresAt?: number,
  ) {
    if (
      !/^[A-Za-z0-9_.:-]{1,128}$/.test(instanceId) ||
      (purpose !== 'distribution-key' && purpose !== 'p8')
    )
      reject();
    const snapshot = { ...lease };
    if (
      maxExpiresAt !== undefined &&
      (!Number.isSafeInteger(maxExpiresAt) || maxExpiresAt <= this.#now())
    )
      reject();
    const expiresAt = Math.min(
      snapshot.expiresAt,
      this.#now() + 120000,
      maxExpiresAt ?? Number.POSITIVE_INFINITY,
    );
    const grantNonce = token();
    const issued = await this.#vault.prepareBootstrapEnvelope(snapshot, purpose, {
      grantNonce,
      audience: this.#audience,
      instanceId,
      expiresAt,
    });
    try {
      const unsigned = {
        version: 1 as const,
        operation: 'bootstrap-seal' as const,
        lease: snapshot,
        secretId: issued.secretId,
        grantNonce,
        audience: this.#audience,
        instanceId,
        purpose,
        materialFormat:
          purpose === 'distribution-key'
            ? ('encrypted-pem-with-password-v1' as const)
            : ('p8-pem-v1' as const),
        expiresAt,
        wrappedKey: issued.wrappedKey,
        aad: issued.aad,
      };
      const signature = createHmac('sha256', this.#proofKey)
        .update('isign-bootstrap-grant-v1\0' + canonicalReport(unsigned))
        .digest('hex');
      return { grant: { ...unsigned, signature }, dataKey: issued.dataKey };
    } catch (error) {
      issued.dataKey.fill(0);
      throw error;
    }
  }
  async commit(
    lease: BootstrapLease,
    receipt: BootstrapEnvelopeReceipt,
  ): Promise<BootstrapIdentity> {
    exactKeys(receipt, ['report', 'attestation']);
    exactKeys(receipt.report, [
      'version',
      'operation',
      'grant',
      'materialFormat',
      'envelope',
      'csr',
      'spkiSha256',
      'ciphertextSha256',
    ]);
    const report = receipt.report;
    const grant = report.grant;
    exactKeys(grant, [
      'version',
      'operation',
      'lease',
      'secretId',
      'grantNonce',
      'audience',
      'instanceId',
      'purpose',
      'materialFormat',
      'expiresAt',
      'wrappedKey',
      'aad',
      'signature',
    ]);
    exactKeys(grant.lease, ['ownerId', 'connectionId', 'generation', 'nonce', 'expiresAt']);
    const { signature, ...unsigned } = grant;
    if (
      report.version !== 1 ||
      report.operation !== 'bootstrap-envelope' ||
      grant.version !== 1 ||
      grant.operation !== 'bootstrap-seal' ||
      grant.audience !== this.#audience ||
      !Number.isSafeInteger(grant.expiresAt) ||
      grant.expiresAt <= this.#now() ||
      grant.expiresAt > lease.expiresAt ||
      canonicalReport(grant.lease) !== canonicalReport(lease) ||
      !authenticated(this.#proofKey, 'isign-bootstrap-grant-v1', unsigned, signature) ||
      !authenticated(this.#proofKey, 'isign-bootstrap-envelope-v1', report, receipt.attestation)
    )
      reject();
    if (
      report.materialFormat !== grant.materialFormat ||
      grant.materialFormat !==
        (grant.purpose === 'distribution-key' ? 'encrypted-pem-with-password-v1' : 'p8-pem-v1')
    )
      reject();
    exactKeys(report.envelope, [
      'secretId',
      'grantNonce',
      'audience',
      'instanceId',
      'purpose',
      'expiresAt',
      'wrappedKey',
      'aad',
      'nonce',
      'ciphertext',
      'tag',
    ]);
    for (const field of [
      'secretId',
      'grantNonce',
      'audience',
      'instanceId',
      'purpose',
      'expiresAt',
      'wrappedKey',
      'aad',
    ] as const)
      if (report.envelope[field] !== grant[field]) reject();
    decodeBootstrapBase64(report.envelope.nonce, 12, 12);
    decodeBootstrapBase64(report.envelope.tag, 16, 16);
    const ciphertext = decodeBootstrapBase64(report.envelope.ciphertext, 65536);
    if (createHash('sha256').update(ciphertext).digest('hex') !== report.ciphertextSha256) reject();
    const csr = bootstrapCsrSpki(report.csr);
    if (
      csr.spkiSha256 !== report.spkiSha256 ||
      (grant.purpose === 'distribution-key' && csr.keyType !== 'rsa')
    )
      reject();
    const secretRef = await this.#vault.acceptBootstrapEnvelope(lease, mint(report.envelope));
    return { secretRef, csr: report.csr, spkiSha256: csr.spkiSha256 };
  }
}
