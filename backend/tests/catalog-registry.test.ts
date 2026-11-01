import { loginFixture } from './helpers/login';
import { it, expect, afterEach } from 'vitest';
import { createDatabase } from './helpers/database';
import { Service } from '../packages/core/src/application/service';
import { CatalogRegistry } from '../packages/core/src/catalog/registry';
const close: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const c of close.splice(0)) await c();
});
async function setup() {
  const db = await createDatabase();
  close.push(() => db.close());
  const mail = new Map<string, string>();
  const s = new Service(db, {
    now: () => 10000,
  });
  async function owner(e: string) {
    return (await loginFixture(s.db, e, s.now)).ownerId;
  }
  return {
    db,
    s,
    a: await owner('one@example.invalid'),
    b: await owner('two@example.invalid'),
    registry: new CatalogRegistry(db, () => 10000),
  };
}
const feed = (version = '1.0') => ({
  appRepositories: [
    {
      appName: 'Own synthetic fixture',
      appVersion: version,
      appPackage: 'https://files.example.invalid/test.ipa',
    },
  ],
});
it('does not fake a live iApps feed and accepts an explicit bounded snapshot', async () => {
  const h = await setup();
  await h.registry.ensureBuiltIn(h.a);
  const sources = await h.registry.list(h.a);
  expect(sources[0].state).toBe('action_required');
  await expect(
    h.registry.snapshot(h.a, sources[0].id, feed(), ['files.example.invalid']),
  ).rejects.toThrow('SOURCE_METADATA_ONLY');
  const custom = await h.registry.add(h.a, 'Fixture', 'https://files.example.invalid/feed.json', [
    'files.example.invalid',
  ]);
  const result = await h.registry.snapshot(h.a, custom.id, feed(), ['files.example.invalid']);
  expect(result.count).toBe(1);
  expect((await h.registry.list(h.a)).find((x) => x.id === custom.id)?.state).toBe('ready');
});
it('rejects foreign source IDs and keeps equal app IDs from different sources separate', async () => {
  const h = await setup();
  await h.registry.ensureBuiltIn(h.a);
  await h.registry.ensureBuiltIn(h.b);
  const a = await h.registry.add(h.a, 'Fixture', 'https://files.example.invalid/feed.json', [
    'files.example.invalid',
  ]);
  await expect(h.registry.snapshot(h.b, a.id, feed(), ['files.example.invalid'])).rejects.toThrow(
    'NOT_FOUND',
  );
  await h.registry.snapshot(h.a, a.id, feed(), ['files.example.invalid']);
  expect((await h.registry.releases(h.a, a.id))[0].sourceId).toBe(a.id);
  await expect(h.registry.releases(h.b, a.id)).rejects.toThrow('NOT_FOUND');
});
it('stale snapshot or removed release cannot silently select latest', async () => {
  const h = await setup();
  await h.registry.ensureBuiltIn(h.a);
  const a = await h.registry.add(h.a, 'Fixture', 'https://files.example.invalid/feed.json', [
    'files.example.invalid',
  ]);
  await h.registry.snapshot(h.a, a.id, feed(), ['files.example.invalid']);
  const first = (await h.registry.releases(h.a, a.id))[0];
  await h.registry.snapshot(h.a, a.id, feed('2.0'), ['files.example.invalid']);
  await expect(h.registry.selection(h.a, a.id, first.id, first.snapshot)).rejects.toThrow(
    'RELEASE_UNAVAILABLE',
  );
});
it('disabling source blocks new selection without deleting imported history', async () => {
  const h = await setup();
  await h.registry.ensureBuiltIn(h.a);
  const a = await h.registry.add(h.a, 'Fixture', 'https://files.example.invalid/feed.json', [
    'files.example.invalid',
  ]);
  await h.registry.snapshot(h.a, a.id, feed(), ['files.example.invalid']);
  const r = (await h.registry.releases(h.a, a.id))[0];
  await h.registry.disable(h.a, a.id);
  await expect(h.registry.selection(h.a, a.id, r.id, r.snapshot)).rejects.toThrow(
    'SOURCE_DISABLED',
  );
});
it('persists the real authorized GBox snapshot and selects query releases without exposing package URLs', async () => {
  const { readFile } = await import('node:fs/promises');
  const input = JSON.parse(
    await readFile(
      new URL('./fixtures/iapps-full-repository-decoded.json', import.meta.url),
      'utf8',
    ),
  );
  const h = await setup();
  const source = await h.registry.add(
    h.a,
    'Authorized iApps snapshot',
    'https://iapps.rejail.ru/export.json',
    ['storage.iapps.rejail.ru', 'github.com'],
  );
  const result = await h.registry.snapshot(h.a, source.id, input, [
    'storage.iapps.rejail.ru',
    'github.com',
  ]);
  expect(result.count).toBe(input.appRepositories.length);
  const releases = await h.registry.releases(h.a, source.id);
  expect(releases.length).toBe(result.count);
  expect(releases.every((r) => !('url' in r))).toBe(true);
  const record = await h.db.query<{ id: string }>(
    "SELECT id FROM releases WHERE source_id=$1 AND metadata->>'url' LIKE '%?raw=true' LIMIT 1",
    [source.id],
  );
  expect(record.rows.length).toBe(1);
  const selected = await h.registry.selection(h.a, source.id, record.rows[0].id, result.snapshot);
  expect(new URL(selected.release.url).searchParams.get('raw')).toBe('true');
  await expect(
    h.registry.selection(h.b, source.id, record.rows[0].id, result.snapshot),
  ).rejects.toThrow('NOT_FOUND');
});
it('refreshes current full publisher feed with ownership and preserves snapshot on corrupt ciphertext', async () => {
  const { readFile } = await import('node:fs/promises');
  const { CURRENT_GBOX_URL } = await import('../packages/core/src/catalog/feed');
  const raw = await readFile(new URL('./fixtures/iapps-current-encrypted.json', import.meta.url));
  const h = await setup();
  let changed = false;
  let now = 1000;
  const registry = new CatalogRegistry(
    h.db,
    () => now,
    async (url) => {
      expect(url).toBe(CURRENT_GBOX_URL);
      return changed ? Buffer.from('{"appRepositories":"new"}') : raw;
    },
  );
  await registry.ensureBuiltIn(h.a);
  const source = (await registry.list(h.a))[0];
  const refreshed = await registry.refresh(h.a, source.id);
  expect(refreshed.count).toBe(1654);
  const releases = await registry.releases(h.a, source.id);
  expect(releases.filter((r) => r.downloadAvailable)).toHaveLength(1652);
  const selected = releases.find((r) => r.downloadAvailable)!;
  expect(
    (await registry.selection(h.a, source.id, selected.id, selected.snapshot)).release.name,
  ).toBe(selected.name);
  await expect(registry.selection(h.b, source.id, selected.id, selected.snapshot)).rejects.toThrow(
    'NOT_FOUND',
  );
  const informational = releases.find((r) => !r.downloadAvailable)!;
  await expect(
    registry.selection(h.a, source.id, informational.id, informational.snapshot),
  ).rejects.toThrow('SOURCE_METADATA_ONLY');
  changed = true;
  now += CatalogRegistry.refreshIntervalMs;
  await expect(registry.refresh(h.a, source.id)).rejects.toThrow('GBOX_DECRYPT_FAILED');
  expect((await registry.releases(h.a, source.id)).map((r) => r.snapshot)).toEqual(
    releases.map((r) => r.snapshot),
  );
  expect((await registry.list(h.a))[0].last_error).toBe('GBOX_DECRYPT_FAILED');
});
