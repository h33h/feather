import { test, expect } from 'vitest';
import { readFile } from 'node:fs/promises';
import { CURRENT_GBOX_URL, decodeFeed } from '../packages/core/src/catalog/feed';
import { normalizeGBox } from '../packages/core/src/catalog/gbox';

test('plain full catalog retains 1654 entries and 1652 actual packages', async () => {
  const bytes = await readFile(
    new URL('./fixtures/iapps-full-repository-decoded.json', import.meta.url),
  );
  const releases = normalizeGBox(
    await decodeFeed(bytes, 'https://source.example.invalid/repo.json'),
  );
  expect(releases).toHaveLength(1654);
  expect(releases.filter((r) => r.url)).toHaveLength(1652);
});

test('decrypts the fresh publisher export instead of using the stored catalog', async () => {
  const bytes = await readFile(new URL('./fixtures/iapps-updated-encrypted.json', import.meta.url));
  const releases = normalizeGBox(await decodeFeed(bytes, CURRENT_GBOX_URL));
  expect(releases).toHaveLength(1);
  expect(releases[0]).toMatchObject({
    name: 'Synthetic iApps refresh',
    version: '2.0',
    url: 'https://storage.iapps.rejail.ru/s/synthetic/download/synthetic.ipa',
  });
});

test('decrypts the existing publisher export with real package URLs', async () => {
  const bytes = await readFile(new URL('./fixtures/iapps-current-encrypted.json', import.meta.url));
  const releases = normalizeGBox(await decodeFeed(bytes, CURRENT_GBOX_URL));
  expect(releases).toHaveLength(1654);
  expect(releases.filter((r) => r.url)).toHaveLength(1652);
});

test('corrupt or foreign encrypted exports never fall back to a stored catalog', async () => {
  const bytes = await readFile(new URL('./fixtures/iapps-updated-encrypted.json', import.meta.url));
  await expect(decodeFeed(bytes, 'https://other.example.invalid/feed.json')).rejects.toThrow(
    'GBOX_EXPORT_CHANGED',
  );
  const input = JSON.parse(bytes.toString());
  input.appRepositories = 'corrupted';
  await expect(decodeFeed(Buffer.from(JSON.stringify(input)), CURRENT_GBOX_URL)).rejects.toThrow(
    'GBOX_DECRYPT_FAILED',
  );
  await expect(decodeFeed(Buffer.from('{'), CURRENT_GBOX_URL)).rejects.toThrow(
    'UNSUPPORTED_GBOX_SCHEMA',
  );
});
