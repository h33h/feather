import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { ProviderError, requireServer } from './config';
import type { Kms } from '../apple/vault';
/** Secret validity/deletion is enforced by Vault's database guards, not a restore ledger. */
export class LocalEnvelopeKms implements Kms {
  constructor(private options: { keyFile: string }) {
    requireServer();
  }
  private async key() {
    const handle = await open(this.options.keyFile, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const info = await handle.stat();
      if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size !== 32)
        throw new ProviderError('PERSONAL_VAULT_STATE_INVALID');
      return await handle.readFile();
    } finally {
      await handle.close();
    }
  }
  private context(context: string) {
    if (!context || context.length > 4096) throw new ProviderError('KMS_CONTEXT_INVALID');
  }
  async assertReady() {
    const key = await this.key();
    key.fill(0);
  }
  async generate(context: string) {
    this.context(context);
    const key = await this.key(),
      plaintext = randomBytes(32);
    try {
      const nonce = randomBytes(12),
        cipher = createCipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(Buffer.from(context));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return {
        plaintext,
        wrapped: JSON.stringify({
          v: 1,
          nonce: nonce.toString('base64'),
          ciphertext: ciphertext.toString('base64'),
          tag: cipher.getAuthTag().toString('base64'),
        }),
      };
    } catch (error) {
      plaintext.fill(0);
      throw error;
    } finally {
      key.fill(0);
    }
  }
  async unwrap(wrapped: string, context: string) {
    this.context(context);
    const key = await this.key();
    try {
      if (wrapped.length > 1024) throw Error();
      const row = JSON.parse(wrapped);
      if (row.v !== 1) throw Error();
      const decode = (value: unknown, size: number) => {
        if (typeof value !== 'string') throw Error();
        const bytes = Buffer.from(value, 'base64');
        if (bytes.length !== size || bytes.toString('base64') !== value) throw Error();
        return bytes;
      };
      const cipher = createDecipheriv('aes-256-gcm', key, decode(row.nonce, 12));
      cipher.setAAD(Buffer.from(context));
      cipher.setAuthTag(decode(row.tag, 16));
      return Buffer.concat([cipher.update(decode(row.ciphertext, 32)), cipher.final()]);
    } catch {
      throw new ProviderError('KMS_KEY_INVALID');
    } finally {
      key.fill(0);
    }
  }
  async revoke(_wrapped: string, _context: string) {
    // Vault marks the row deleted before clearing wrapped/ciphertext fields.
  }
}
