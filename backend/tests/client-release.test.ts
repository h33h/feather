import { afterEach, expect, it, vi } from 'vitest';
import { mkdtemp, rm, writeFile, rename, stat, utimes, symlink } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { LocalClientRelease } from '../packages/core/src/infrastructure/client-release';
vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, createHash: vi.fn(actual.createHash) };
});
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});
async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), 'client-release-'));
  directories.push(directory);
  const file = path.join(directory, 'official.ipa');
  await writeFile(file, 'official source');
  const digest = createHash('sha256').update('official source').digest('hex');
  return {
    file,
    digest,
    env: {
      ISIGN_CLIENT_IPA_PATH: file,
      ISIGN_CLIENT_IPA_SHA256: digest,
      ISIGN_CLIENT_VERSION: '1.2.3',
    },
  };
}
it('reports absent or malformed release settings without disclosing private configuration', async () => {
  for (const env of [
    {},
    { ISIGN_CLIENT_IPA_PATH: '/private/operator.ipa' },
    { ISIGN_CLIENT_IPA_PATH: 'relative.ipa', ISIGN_CLIENT_IPA_SHA256: 'a'.repeat(64) },
    { ISIGN_CLIENT_IPA_PATH: '/private/operator.ipa', ISIGN_CLIENT_IPA_SHA256: 'malformed' },
  ]) {
    const status = await new LocalClientRelease(env).status();
    expect(status).toMatchObject({
      name: 'iSign Client',
      available: false,
      reason: expect.stringMatching(/^CLIENT_RELEASE_/),
    });
    expect(JSON.stringify(status)).not.toMatch(/private|operator|relative|malformed/);
  }
});
it('exposes a versioned release only when the pinned checksum matches readable bytes', async () => {
  const f = await fixture(),
    release = new LocalClientRelease(f.env);
  expect(await release.status()).toEqual({
    name: 'iSign Client',
    available: true,
    version: '1.2.3',
  });
  const source = await release.open();
  const chunks: Uint8Array[] = [];
  for await (const chunk of source.bytes) chunks.push(chunk);
  expect(Buffer.concat(chunks).toString()).toBe('official source');
  expect(source.digest).toBe(f.digest);
  await writeFile(f.file, 'changed source');
  expect(await release.status()).toMatchObject({
    available: false,
    reason: 'CLIENT_RELEASE_CHECKSUM_MISMATCH',
  });
  await expect(release.open()).rejects.toThrow('CLIENT_RELEASE_CHECKSUM_MISMATCH');
});
it('checks the streaming source again so mutation between inspection and receive cannot enter the pipeline', async () => {
  const f = await fixture(),
    release = new LocalClientRelease(f.env),
    source = await release.open();
  await writeFile(f.file, 'replaced bytes');
  await expect(
    (async () => {
      for await (const chunk of source.bytes) void chunk;
    })(),
  ).rejects.toThrow('CLIENT_RELEASE_CHECKSUM_MISMATCH');
  await rm(f.file);
  expect(await release.status()).toMatchObject({
    available: false,
    reason: 'CLIENT_RELEASE_UNAVAILABLE',
  });
});

it('coalesces public status hashing and reuses it only within the metadata-bound five-second TTL', async () => {
  const f = await fixture();
  let now = 1000;
  const release = new LocalClientRelease(f.env, { now: () => now });
  vi.mocked(createHash).mockClear();
  const results = await Promise.all(Array.from({ length: 12 }, () => release.status()));
  expect(results.every((result) => result.available)).toBe(true);
  expect(createHash).toHaveBeenCalledTimes(1);
  expect(await release.status()).toMatchObject({ available: true });
  expect(createHash).toHaveBeenCalledTimes(1);
  now += 5000;
  expect(await release.status()).toMatchObject({ available: true });
  expect(createHash).toHaveBeenCalledTimes(2);
});
it('invalidates a warm status cache when the file is replaced with the same length and mtime', async () => {
  const f = await fixture(),
    release = new LocalClientRelease(f.env);
  expect(await release.status()).toMatchObject({ available: true });
  const previous = await stat(f.file),
    replacement = f.file + '.replacement';
  await writeFile(replacement, 'changed source');
  await utimes(replacement, previous.atime, previous.mtime);
  await rename(replacement, f.file);
  expect(await release.status()).toMatchObject({
    available: false,
    reason: 'CLIENT_RELEASE_CHECKSUM_MISMATCH',
  });
  await expect(release.open()).rejects.toThrow('CLIENT_RELEASE_CHECKSUM_MISMATCH');
});
it('always rehashes actual installation admission and source streaming even while public status is cached', async () => {
  const f = await fixture(),
    release = new LocalClientRelease(f.env);
  expect(await release.status()).toMatchObject({ available: true });
  vi.mocked(createHash).mockClear();
  const source = await release.open();
  expect(createHash).toHaveBeenCalledTimes(1);
  for await (const chunk of source.bytes) void chunk;
  expect(createHash).toHaveBeenCalledTimes(2);
});
it('refuses symlinks after a warm status cache and never exposes the target path', async () => {
  const f = await fixture(),
    release = new LocalClientRelease(f.env);
  expect(await release.status()).toMatchObject({ available: true });
  const target = f.file + '.target';
  await rename(f.file, target);
  await symlink(target, f.file);
  const result = await release.status();
  expect(result).toMatchObject({ available: false, reason: 'CLIENT_RELEASE_UNAVAILABLE' });
  expect(JSON.stringify(result)).not.toContain(target);
  await expect(release.open()).rejects.toThrow('CLIENT_RELEASE_UNAVAILABLE');
});
it('bounds hashing for an unchanged checksum mismatch while retaining safe unavailable status', async () => {
  const f = await fixture();
  await writeFile(f.file, 'changed source');
  const release = new LocalClientRelease(f.env);
  vi.mocked(createHash).mockClear();
  const expected = {
    name: 'iSign Client',
    available: false,
    reason: 'CLIENT_RELEASE_CHECKSUM_MISMATCH',
  };
  expect(await release.status()).toEqual(expected);
  expect(await release.status()).toEqual(expected);
  expect(createHash).toHaveBeenCalledTimes(1);
  await expect(release.open()).rejects.toThrow('CLIENT_RELEASE_CHECKSUM_MISMATCH');
  expect(createHash).toHaveBeenCalledTimes(2);
});
