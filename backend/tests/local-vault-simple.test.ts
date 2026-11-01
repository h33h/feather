import { afterEach, expect, it } from 'vitest';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import { LocalEnvelopeKms } from '../packages/core/src/infrastructure/local-kms';
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});
it('wraps new material with a private local key and rejects a different authenticated context', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'isign-kms-test-'));
  directories.push(dir);
  const keyFile = path.join(dir, 'key');
  await writeFile(keyFile, randomBytes(32), { mode: 0o600 });
  const kms = new LocalEnvelopeKms({ keyFile } as ConstructorParameters<
    typeof LocalEnvelopeKms
  >[0]);
  await kms.assertReady();
  const material = await kms.generate('owner:connection:p8:secret');
  expect(
    (await kms.unwrap(material.wrapped, 'owner:connection:p8:secret')).equals(material.plaintext),
  ).toBe(true);
  await expect(kms.unwrap(material.wrapped, 'other:connection:p8:secret')).rejects.toThrow(
    'KMS_KEY_INVALID',
  );
  material.plaintext.fill(0);
});
