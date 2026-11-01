import { describe, it, expect, vi } from 'vitest';
import { createCipheriv, createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { Vault, type Kms } from '../packages/core/src/apple/vault';
import { DatabaseBootstrapPort } from '../packages/core/src/apple/bootstrap-store';
import {
  BootstrapSealing,
  bootstrapCsrSpki,
  type BootstrapEnvelopeReceipt,
  type BootstrapSealingGrant,
  type VerifiedBootstrapEnvelope,
} from '../packages/core/src/apple/bootstrap-sealing';
import { canonicalReport } from '../packages/core/src/shared/canonical-json';
function der(tag: number, ...values: Buffer[]) {
  const body = Buffer.concat(values);
  let length: Buffer;
  if (body.length < 128) length = Buffer.from([body.length]);
  else {
    const hex = body.length.toString(16).padStart(body.length > 255 ? 4 : 2, '0');
    const bytes = Buffer.from(hex, 'hex');
    length = Buffer.concat([Buffer.from([128 | bytes.length]), bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), length, body]);
}
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
const request = der(0x30, Buffer.from('020100', 'hex'), der(0x30), spki, der(0xa0));
const csrDer = der(
  0x30,
  request,
  der(0x30, Buffer.from('06092a864886f70d01010b0500', 'hex')),
  der(3, Buffer.from([0]), sign('sha256', request, pair.privateKey)),
);
const csr =
  '-----BEGIN CERTIFICATE REQUEST-----\n' +
  csrDer
    .toString('base64')
    .match(/.{1,64}/g)!
    .join('\n') +
  '\n-----END CERTIFICATE REQUEST-----\n';
const proofKey = Buffer.alloc(32, 9);
function attest(report: BootstrapEnvelopeReceipt['report']) {
  return {
    report,
    attestation: createHmac('sha256', proofKey)
      .update('isign-bootstrap-envelope-v1\0' + canonicalReport(report))
      .digest('hex'),
  };
}
function guestReceipt(grant: BootstrapSealingGrant, key: Buffer) {
  const nonce = Buffer.alloc(12, 7);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.from(grant.aad));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from('synthetic guest-only private payload')),
    cipher.final(),
  ]);
  const { secretId, grantNonce, audience, instanceId, purpose, expiresAt, wrappedKey, aad } = grant;
  return attest({
    version: 1,
    operation: 'bootstrap-envelope',
    grant,
    materialFormat: grant.materialFormat,
    envelope: {
      secretId,
      grantNonce,
      audience,
      instanceId,
      purpose,
      expiresAt,
      wrappedKey,
      aad,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
    },
    csr,
    spkiSha256: createHash('sha256').update(spki).digest('hex'),
    ciphertextSha256: createHash('sha256').update(ciphertext).digest('hex'),
  });
}
async function fixture() {
  const db = await createDatabase();
  let now = 10000;
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner@example.test',0)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('connection','owner','pending:connection','validating','asc')",
  );
  let generated: Buffer | undefined;
  let generateHook: (() => Promise<void>) | undefined;
  const kms: Kms = {
    generate: vi.fn(async () => {
      generated = Buffer.alloc(32, 5);
      await generateHook?.();
      return { plaintext: generated, wrapped: 'synthetic KMS ciphertext envelope' };
    }),
    unwrap: vi.fn(async () => {
      throw Error('private payload must never be decrypted by receipt acceptance');
    }),
  };
  const vault = new Vault(db, kms, () => now);
  const bootstrap = new DatabaseBootstrapPort({
    db,
    now: () => now,
    prepareIdentity: async () => {
      throw Error('unused');
    },
    findCertificates: async () => [],
    createCertificate: async () => {
      throw Error('unused');
    },
  });
  const lease = await bootstrap.acquire('owner', 'connection', 1);
  const bridge = new BootstrapSealing({
    vault,
    proofKey,
    audience: 'isign-bootstrap',
    now: () => now,
  });
  return {
    db,
    vault,
    kms,
    bridge,
    lease,
    advance: (value: number) => {
      now += value;
    },
    generated: () => generated,
    setGenerateHook: (hook: () => Promise<void>) => {
      generateHook = hook;
    },
  };
}
describe('authenticated bootstrap ciphertext bridge', () => {
  it('verifies a bounded public CSR signature and its SPKI without parsing private material', () => {
    expect(bootstrapCsrSpki(csr)).toEqual({
      spkiSha256: createHash('sha256').update(spki).digest('hex'),
      keyType: 'rsa',
    });
    const changed = Buffer.from(csrDer);
    changed[changed.length - 1] ^= 1;
    const malformed =
      '-----BEGIN CERTIFICATE REQUEST-----\n' +
      changed.toString('base64') +
      '\n-----END CERTIFICATE REQUEST-----\n';
    expect(() => bootstrapCsrSpki(malformed)).toThrow('BOOTSTRAP_ENVELOPE_INVALID');
    expect(() => bootstrapCsrSpki('browser CSR assertion')).toThrow('BOOTSTRAP_ENVELOPE_INVALID');
  });
  it('issues a server-owned context and atomically accepts ciphertext only once without unwrap', async () => {
    const f = await fixture();
    try {
      const issued = await f.bridge.issue(f.lease, 'distribution-key', 'synthetic-vm');
      expect(issued.grant.aad).toBe(
        JSON.stringify({
          owner: 'owner',
          connection: 'connection',
          purpose: 'distribution-key',
          secret: issued.grant.secretId,
        }),
      );
      const receipt = guestReceipt(issued.grant, issued.dataKey);
      issued.dataKey.fill(0);
      const identity = await f.bridge.commit(f.lease, receipt);
      expect(identity).toEqual({
        secretRef: issued.grant.secretId,
        csr,
        spkiSha256: receipt.report.spkiSha256,
      });
      expect(f.kms.unwrap).not.toHaveBeenCalled();
      const stored = (
        await f.db.query<{ ciphertext: string; purpose: string }>(
          'SELECT ciphertext,purpose FROM secrets',
        )
      ).rows[0];
      expect(stored.ciphertext).toBe(receipt.report.envelope.ciphertext);
      expect(stored.purpose).toBe('distribution-key');
      expect(
        JSON.stringify((await f.db.query('SELECT * FROM bootstrap_secret_grants')).rows),
      ).not.toContain('synthetic guest-only private payload');
      expect(f.generated()).toEqual(Buffer.alloc(32));
      await expect(f.bridge.commit(f.lease, receipt)).rejects.toThrow('SECRET_UNAVAILABLE');
      expect((await f.db.query('SELECT id FROM secrets')).rows).toHaveLength(1);
    } finally {
      await f.db.close();
    }
  });
  it('rejects browser JSON provenance, forged HMAC, cross-owner leases and changed key context', async () => {
    const f = await fixture();
    try {
      const issued = await f.bridge.issue(f.lease, 'distribution-key', 'synthetic-vm');
      const receipt = guestReceipt(issued.grant, issued.dataKey);
      issued.dataKey.fill(0);
      await expect(
        f.vault.acceptBootstrapEnvelope(f.lease, {
          ...receipt.report.envelope,
          persisted: true,
        } as unknown as VerifiedBootstrapEnvelope),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      await expect(
        f.bridge.commit(f.lease, { ...receipt, attestation: '0'.repeat(64) }),
      ).rejects.toThrow('BOOTSTRAP_ENVELOPE_INVALID');
      await expect(f.bridge.commit({ ...f.lease, ownerId: 'foreign' }, receipt)).rejects.toThrow(
        'BOOTSTRAP_ENVELOPE_INVALID',
      );
      const changed = attest({
        ...receipt.report,
        envelope: { ...receipt.report.envelope, wrappedKey: 'other KMS ciphertext' },
      });
      await expect(f.bridge.commit(f.lease, changed)).rejects.toThrow('BOOTSTRAP_ENVELOPE_INVALID');
      const context = attest({
        ...receipt.report,
        envelope: { ...receipt.report.envelope, aad: 'foreign-context' },
      });
      await expect(f.bridge.commit(f.lease, context)).rejects.toThrow('BOOTSTRAP_ENVELOPE_INVALID');
      expect((await f.db.query('SELECT id FROM secrets')).rows).toHaveLength(0);
      expect(f.kms.unwrap).not.toHaveBeenCalled();
    } finally {
      await f.db.close();
    }
  });
  it('rejects changed ciphertext/CSR/SPKI even under valid broker report authentication', async () => {
    const f = await fixture();
    try {
      const issued = await f.bridge.issue(f.lease, 'distribution-key', 'synthetic-vm');
      const receipt = guestReceipt(issued.grant, issued.dataKey);
      issued.dataKey.fill(0);
      for (const change of [
        { ciphertextSha256: '0'.repeat(64) },
        { csr: 'browser CSR assertion' },
        { spkiSha256: '0'.repeat(64) },
      ])
        await expect(
          f.bridge.commit(f.lease, attest({ ...receipt.report, ...change })),
        ).rejects.toThrow('BOOTSTRAP_ENVELOPE_INVALID');
      expect((await f.db.query('SELECT id FROM secrets')).rows).toHaveLength(0);
    } finally {
      await f.db.close();
    }
  });
  it('fences pending bootstrap replacement/disconnect and expiry after key issuance', async () => {
    const f = await fixture();
    try {
      const issued = await f.bridge.issue(f.lease, 'distribution-key', 'synthetic-vm');
      const receipt = guestReceipt(issued.grant, issued.dataKey);
      issued.dataKey.fill(0);
      await f.db.query(
        "UPDATE connections SET generation=2,state='disconnected' WHERE id='connection'",
      );
      await expect(f.bridge.commit(f.lease, receipt)).rejects.toThrow('SECRET_UNAVAILABLE');
      f.advance(120001);
      await expect(f.bridge.commit(f.lease, receipt)).rejects.toThrow('BOOTSTRAP_ENVELOPE_INVALID');
      expect((await f.db.query('SELECT id FROM secrets')).rows).toHaveLength(0);
    } finally {
      await f.db.close();
    }
  });
  it('zeroes generated data keys when an asynchronous KMS issue loses its lease', async () => {
    const f = await fixture();
    try {
      f.setGenerateHook(async () => {
        await f.db.query(
          "UPDATE bootstrap_operations SET nonce='replacement' WHERE owner_id='owner'",
        );
      });
      await expect(f.bridge.issue(f.lease, 'distribution-key', 'synthetic-vm')).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      expect(f.generated()).toEqual(Buffer.alloc(32));
      expect((await f.db.query('SELECT secret_id FROM bootstrap_secret_grants')).rows).toHaveLength(
        0,
      );
    } finally {
      await f.db.close();
    }
  });
});

it('caps bootstrap seal lifetime to the authenticated VM deadline after launch delay', async () => {
  const f = await fixture();
  try {
    f.advance(3000);
    const issued = await f.bridge.issue(f.lease, 'distribution-key', 'synthetic-vm', 13000 + 60000);
    expect(issued.grant.expiresAt).toBe(73000);
    issued.dataKey.fill(0);
    await expect(f.bridge.issue(f.lease, 'distribution-key', 'expired-vm', 13000)).rejects.toThrow(
      'BOOTSTRAP_ENVELOPE_INVALID',
    );
  } finally {
    await f.db.close();
  }
});
