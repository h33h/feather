import { it, expect } from 'vitest';
import { mkdtemp, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalEnvelopeKms } from '../packages/core/src/infrastructure/local-kms';
it('binds encrypted keys to context, rejects tampering and checks private key permissions after restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'isign-kms-'));
  try {
    const keyFile = join(directory, 'key');
    await writeFile(keyFile, Buffer.alloc(32, 7), { mode: 0o600 });
    const kms = new LocalEnvelopeKms({ keyFile });
    const value = await kms.generate('owner:a');
    expect(await new LocalEnvelopeKms({ keyFile }).unwrap(value.wrapped, 'owner:a')).toEqual(
      value.plaintext,
    );
    await expect(kms.unwrap(value.wrapped, 'owner:b')).rejects.toThrow('KMS_KEY_INVALID');
    const envelope = JSON.parse(value.wrapped);
    envelope.tag = Buffer.alloc(16).toString('base64');
    await expect(kms.unwrap(JSON.stringify(envelope), 'owner:a')).rejects.toThrow(
      'KMS_KEY_INVALID',
    );
    await chmod(keyFile, 0o644);
    await expect(kms.generate('x')).rejects.toThrow('PERSONAL_VAULT_STATE_INVALID');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
