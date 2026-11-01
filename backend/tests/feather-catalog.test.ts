import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { loginFixture } from './helpers/login';
import { CatalogRegistry } from '../packages/core/src/catalog/registry';
import { FeatherCatalog } from '../packages/core/src/catalog/feather-feed';
import {
  fetchSafeStream,
  type Options,
  type Response,
} from '../packages/core/src/catalog/safe-fetch';
import {
  featherFeedSchema,
  featherSourcesSchema,
  featherDownloadSchema,
  sourcesSchema,
} from '../packages/contracts/src';

const host = 'files.example.invalid';
const fixture = () => ({
  identifier: 'example.repo',
  name: 'Example catalog',
  subtitle: 'Subtitle',
  description: 'Repository description',
  website: 'https://example.invalid/',
  iconURL: `https://${host}/repo.png`,
  headerURL: `https://${host}/header.png`,
  tintColor: '#123456',
  patreonURL: 'https://patreon.com/example',
  featuredApps: ['com.example.app'],
  news: [
    {
      identifier: 'news-1',
      title: 'Update',
      caption: 'Try this',
      date: '2026-10-31',
      appID: 'com.example.app',
      imageURL: `https://${host}/news.png`,
      notify: true,
    },
  ],
  apps: [
    {
      name: 'Example app',
      bundleIdentifier: 'com.example.app',
      developerName: 'Example Developer',
      subtitle: 'App subtitle',
      localizedDescription: 'App description',
      iconURL: `https://${host}/app.png`,
      screenshotURLs: [`https://${host}/screen.png`],
      screenshots: {
        iphone: [{ imageURL: `https://${host}/screen.png`, width: 500, height: 1000 }],
        ipad: [`https://${host}/ipad.png`],
      },
      version: '2.0',
      downloadURL: `https://${host}/2.ipa`,
      versionDate: '2026-10-31',
      appPermissions: {
        entitlements: ['aps-environment'],
        privacy: { NSCameraUsageDescription: 'Camera' },
      },
      versions: [
        {
          version: '2.0',
          buildVersion: '20',
          downloadURL: `https://${host}/2.ipa`,
          date: '2026-10-31',
          size: 1024,
          minOSVersion: '16.0',
          localizedDescription: 'New',
        },
        {
          version: '1.0',
          buildVersion: '10',
          downloadURL: `https://${host}/1.ipa`,
          date: '2025-01-01',
          size: '512',
          minOSVersion: '15.0',
        },
      ],
    },
  ],
});
async function setup(input: unknown = fixture()) {
  const db = await createDatabase();
  const now = () => 10000;
  const owner = (await loginFixture(db, 'owner@example.invalid', now())).ownerId;
  const foreign = (await loginFixture(db, 'foreign@example.invalid', now())).ownerId;
  const registry = new CatalogRegistry(db, now, async () => Buffer.from(JSON.stringify(input)));
  const source = await registry.add(owner, 'User name', `https://${host}/feed.json`, [host]);
  const stream = (url: string, options: Options) =>
    fetchSafeStream(url, {
      ...options,
      resolve: async () => [{ address: '93.184.216.34', family: 4 }],
      transport: async () => ({
        status: 200,
        headers: {},
        body: (async function* () {
          yield Buffer.from('IPA');
        })(),
      }),
    });
  const catalog = new FeatherCatalog(db, registry, { now, fetch: stream });
  return { db, owner, foreign, registry, source, catalog, stream, now };
}
function reference(value: string) {
  const url = new URL(value);
  expect(url.protocol).toBe('isign-feather:');
  expect(url.hostname).toBe('download');
  const [sourceId, releaseId] = url.pathname.slice(1).split('/');
  return { sourceId, releaseId, snapshot: url.searchParams.get('snapshot')! };
}

it('ingests real AltStore JSON and preserves repository, app, news and every historical version', async () => {
  const h = await setup();
  await h.registry.refresh(h.owner, h.source.id);
  const list = featherSourcesSchema.parse(await h.catalog.list(h.owner));
  expect(list.sources).toEqual([
    {
      id: h.source.id,
      name: 'User name',
      revision: 1,
      state: 'ready',
      canonicalUrl: `https://${host}/feed.json`,
    },
  ]);
  const feed = featherFeedSchema.parse(await h.catalog.feed(h.owner, h.source.id));
  const expected = fixture();
  const { apps: _apps, ...metadata } = expected;
  expect(feed.repository).toMatchObject(metadata);
  const app = feed.repository.apps[0];
  expect(app).toMatchObject({
    bundleIdentifier: 'com.example.app',
    developerName: 'Example Developer',
    screenshotURLs: expected.apps[0].screenshotURLs,
    screenshots: expected.apps[0].screenshots,
    appPermissions: expected.apps[0].appPermissions,
  });
  expect(app.versions?.map((v) => [v.version, v.buildVersion])).toEqual([
    ['2.0', '20'],
    ['1.0', '10'],
  ]);
  expect(reference(app.downloadURL!)).toEqual(reference(app.versions![0].downloadURL!));
  for (const [index, version] of app.versions!.entries()) {
    const marker = reference(version.downloadURL!);
    expect(marker.sourceId).toBe(h.source.id);
    expect(marker.snapshot).toBe(feed.snapshot);
    expect(featherDownloadSchema.parse(await h.catalog.download(h.owner, marker))).toEqual({
      url: expected.apps[0].versions[index].downloadURL,
      headers: {},
      expiresAt: 70000,
    });
  }
  // Existing web projections continue to hide foreign download URLs.
  expect(JSON.stringify(await h.registry.releases(h.owner, h.source.id))).not.toContain('https://');
  expect(
    sourcesSchema.parse({ sources: await h.registry.list(h.owner) }).sources[0],
  ).not.toHaveProperty('canonical_url');
});

it('converts GBox and metadata-only releases without inventing downloadable URLs', async () => {
  const h = await setup({
    appRepositories: [
      {
        appName: 'GBox app',
        appVersion: '2.0 | Special',
        appBuild: '20',
        appBundleIdentifier: 'com.gbox.app',
        appImage: `https://${host}/icon.png`,
        appPackage: `https://${host}/gbox.ipa`,
        appDescription: 'Description',
      },
      { appName: 'Read me', appVersion: 'Info' },
    ],
  });
  await h.registry.refresh(h.owner, h.source.id);
  const feed = await h.catalog.feed(h.owner, h.source.id);
  const app = feed.repository.apps.find((a) => a.name === 'GBox app')!;
  expect(app).toMatchObject({
    bundleIdentifier: 'com.gbox.app',
    version: '2.0',
    localizedDescription: 'Description',
    iconURL: `https://${host}/icon.png`,
  });
  expect((await h.catalog.download(h.owner, reference(app.downloadURL!))).url).toBe(
    `https://${host}/gbox.ipa`,
  );
  expect(feed.repository.apps.find((a) => a.name === 'Read me')!.downloadURL).toBeUndefined();
  expect(feed.repository.apps.find((a) => a.name === 'Read me')!.iconURL).toBeUndefined();
  const info = (await h.registry.releases(h.owner, h.source.id)).find((r) => !r.downloadAvailable)!;
  await expect(
    h.catalog.download(h.owner, {
      sourceId: h.source.id,
      releaseId: info.id,
      snapshot: feed.snapshot,
    }),
  ).rejects.toThrow('SOURCE_METADATA_ONLY');
});

it('checks ownership, exact source, snapshot and unavailable lifecycle for feed and downloads', async () => {
  const h = await setup();
  await h.registry.refresh(h.owner, h.source.id);
  const feed = await h.catalog.feed(h.owner, h.source.id);
  const marker = reference(feed.repository.apps[0].downloadURL!);
  expect((await h.catalog.list(h.foreign)).sources).toEqual([]);
  await expect(h.catalog.feed(h.foreign, h.source.id)).rejects.toThrow('NOT_FOUND');
  await expect(h.catalog.download(h.foreign, marker)).rejects.toThrow('NOT_FOUND');
  await expect(h.catalog.download(h.owner, { ...marker, sourceId: 'foreign' })).rejects.toThrow(
    'NOT_FOUND',
  );
  await expect(h.catalog.download(h.owner, { ...marker, snapshot: 'stale' })).rejects.toThrow(
    'RELEASE_UNAVAILABLE',
  );
  const changed = fixture();
  changed.description = 'Metadata changed';
  await h.registry.snapshot(h.owner, h.source.id, changed, [host]);
  await expect(h.catalog.download(h.owner, marker)).rejects.toThrow('RELEASE_UNAVAILABLE');
  await h.registry.disable(h.owner, h.source.id);
  await expect(h.catalog.feed(h.owner, h.source.id)).rejects.toThrow('SOURCE_DISABLED');
  await expect(h.catalog.download(h.owner, marker)).rejects.toThrow('SOURCE_DISABLED');
  await h.registry.remove(h.owner, h.source.id);
  expect((await h.catalog.list(h.owner)).sources).toEqual([]);
  await expect(h.catalog.feed(h.owner, h.source.id)).rejects.toThrow('SOURCE_DISABLED');
});

it('refuses unsupported private auth and disallows package hosts outside publisher trust', async () => {
  for (const secret of [
    { headers: { Authorization: 'Bearer source-secret' } },
    { userInfo: { patreonAccessToken: 'source-secret' } },
    { downloadHeaders: { Cookie: 'source-secret' } },
  ]) {
    const h = await setup();
    await expect(
      h.registry.snapshot(h.owner, h.source.id, { ...fixture(), ...secret }, [host]),
    ).rejects.toThrow('SOURCE_AUTH_UNSUPPORTED');
  }
  const h = await setup();
  const input = fixture();
  input.apps[0].versions[1].downloadURL = 'https://foreign.example.invalid/old.ipa';
  await expect(h.registry.snapshot(h.owner, h.source.id, input, [host])).rejects.toThrow(
    'ARTIFACT_HOST_NOT_APPROVED',
  );
});

it('rejects foreign redirects, strips no trust checks, and never forwards native or source credentials', async () => {
  const h = await setup();
  await h.registry.refresh(h.owner, h.source.id);
  const marker = reference(
    (await h.catalog.feed(h.owner, h.source.id)).repository.apps[0].downloadURL!,
  );
  const catalog = new FeatherCatalog(h.db, h.registry, {
    now: h.now,
    fetch: (url, options) =>
      fetchSafeStream(url, {
        ...options,
        resolve: async () => [{ address: '93.184.216.34', family: 4 }],
        transport: async (_url, _address, headers) => {
          expect(headers).not.toHaveProperty('authorization');
          expect(headers).not.toHaveProperty('cookie');
          return {
            status: 302,
            headers: { location: 'https://foreign.example.invalid/file.ipa' },
            body: (async function* () {})(),
          };
        },
      }),
  });
  await expect(catalog.download(h.owner, marker)).rejects.toThrow('ARTIFACT_HOST_NOT_APPROVED');
  await h.db.query(
    "UPDATE releases SET metadata=jsonb_set(metadata,'{url}',to_jsonb($2::text)) WHERE source_id=$1",
    [h.source.id, 'https://foreign.example.invalid/file.ipa'],
  );
  await expect(h.catalog.download(h.owner, marker)).rejects.toThrow('ARTIFACT_HOST_NOT_APPROVED');
});

it('returns only an approved final HTTPS target and closes the remote body without consuming IPA bytes', async () => {
  const h = await setup();
  await h.registry.refresh(h.owner, h.source.id);
  const marker = reference(
    (await h.catalog.feed(h.owner, h.source.id)).repository.apps[0].downloadURL!,
  );
  let reads = 0,
    closed = 0;
  const signals: AbortSignal[] = [];
  const catalog = new FeatherCatalog(h.db, h.registry, {
    now: h.now,
    fetch: (url, options) =>
      fetchSafeStream(url, {
        ...options,
        resolve: async () => [{ address: '93.184.216.34', family: 4 }],
        transport: async (target, _address, headers, signal): Promise<Response> => {
          signals.push(signal);
          expect(headers).not.toHaveProperty('authorization');
          expect(headers).not.toHaveProperty('cookie');
          const body: AsyncIterable<Uint8Array> = {
            [Symbol.asyncIterator]: () => ({
              next: async () => {
                reads++;
                return { done: false, value: Buffer.alloc(1024) };
              },
              return: async () => {
                closed++;
                return { done: true, value: undefined };
              },
            }),
          };
          return target.pathname === '/2.ipa'
            ? { status: 302, headers: { location: '/final.ipa?sig=resource-only' }, body }
            : { status: 200, headers: { 'content-length': '104857600' }, body };
        },
      }),
  });
  expect(await catalog.download(h.owner, marker)).toEqual({
    url: `https://${host}/final.ipa?sig=resource-only`,
    headers: {},
    expiresAt: 70000,
  });
  expect(reads).toBe(0);
  expect(closed).toBe(2);
  expect(signals.every((signal) => signal.aborted)).toBe(true);
});

it('rejects private DNS targets and obsolete selections after a preflight while closing the connection', async () => {
  const h = await setup();
  await h.registry.refresh(h.owner, h.source.id);
  const marker = reference(
    (await h.catalog.feed(h.owner, h.source.id)).repository.apps[0].downloadURL!,
  );
  const privateTarget = new FeatherCatalog(h.db, h.registry, {
    now: h.now,
    fetch: (url, options) =>
      fetchSafeStream(url, {
        ...options,
        resolve: async () => [{ address: '127.0.0.1', family: 4 }],
        transport: async () => {
          throw new Error('Private IP must not be fetched');
        },
      }),
  });
  await expect(privateTarget.download(h.owner, marker)).rejects.toThrow('SSRF_BLOCKED');
  let closed = false;
  const disabling = new FeatherCatalog(h.db, h.registry, {
    now: h.now,
    fetch: async (url, options) => {
      const response = await h.stream(url, options);
      await h.registry.disable(h.owner, h.source.id);
      return {
        ...response,
        close: async () => {
          closed = true;
          await response.close();
        },
      };
    },
  });
  await expect(disabling.download(h.owner, marker)).rejects.toThrow('SOURCE_DISABLED');
  expect(closed).toBe(true);
  await expect(
    h.catalog.download(h.owner, { ...marker, releaseId: 'x'.repeat(201) }),
  ).rejects.toThrow('INVALID_DOWNLOAD_REFERENCE');
});

it('adapts stored GBox snapshots created before the native JSONB extensions', async () => {
  const h = await setup({
    appRepositories: [
      { appName: 'Legacy app', appVersion: '1.0', appPackage: `https://${host}/legacy.ipa` },
    ],
  });
  await h.registry.refresh(h.owner, h.source.id);
  await h.db.query("UPDATE sources SET feed=feed-'snapshot'-'repository' WHERE id=$1", [
    h.source.id,
  ]);
  const feed = featherFeedSchema.parse(await h.catalog.feed(h.owner, h.source.id));
  expect(feed.repository.apps[0].name).toBe('Legacy app');
  expect(
    (await h.catalog.download(h.owner, reference(feed.repository.apps[0].downloadURL!))).url,
  ).toBe(`https://${host}/legacy.ipa`);
});

it('preserves supported GBox repository metadata and app update information', async () => {
  const h = await setup({
    sourceName: 'Publisher name',
    sourceDescription: 'Publisher description',
    sourceImage: `https://${host}/publisher.png`,
    sourceLinkUrl: 'https://example.invalid/',
    appRepositories: [
      {
        appName: 'GBox app',
        appVersion: '2.0',
        appUpdateTime: '2026-10-31',
        appPackage: `https://${host}/gbox.ipa`,
      },
    ],
  });
  await h.registry.refresh(h.owner, h.source.id);
  const feed = await h.catalog.feed(h.owner, h.source.id);
  expect(feed.repository).toMatchObject({
    name: 'Publisher name',
    description: 'Publisher description',
    iconURL: `https://${host}/publisher.png`,
    website: 'https://example.invalid/',
  });
  expect(feed.repository.apps[0].versionDate).toBe('2026-10-31');
});

it('keeps empty-version legacy GBox information entries readable', async () => {
  const h = await setup({ appRepositories: [{ appName: 'Information', appVersion: '' }] });
  await h.registry.refresh(h.owner, h.source.id);
  await h.db.query("UPDATE sources SET feed=feed-'snapshot'-'repository' WHERE id=$1", [
    h.source.id,
  ]);
  const feed = await h.catalog.feed(h.owner, h.source.id);
  expect(feed.repository.apps[0].name).toBe('Information');
  expect(feed.repository.apps[0].versions).toBeUndefined();
  expect(feed.repository.apps[0].downloadURL).toBeUndefined();
});

it('accepts explicit null optional AltStore metadata as absent without accepting required null fields', async () => {
  const input = fixture();
  const nullable = {
    ...input,
    description: null,
    website: null,
    news: null,
    featuredApps: null,
    userInfo: { patreonAccessToken: null },
    apps: input.apps.map((app) => ({
      ...app,
      iconURL: null,
      screenshotURLs: null,
      screenshots: null,
      appPermissions: null,
      versionDate: null,
      versions: app.versions.map((version) => ({
        ...version,
        localizedDescription: null,
        size: null,
        minOSVersion: null,
      })),
    })),
  };
  const h = await setup(nullable);
  await h.registry.refresh(h.owner, h.source.id);
  const feed = await h.catalog.feed(h.owner, h.source.id);
  expect(feed.repository.description).toBeUndefined();
  expect(feed.repository.news).toBeUndefined();
  expect(feed.repository.apps[0].iconURL).toBeUndefined();
  expect(feed.repository.apps[0].versions![0]).toMatchObject({
    version: '2.0',
    buildVersion: '20',
  });
  expect(feed.repository.apps[0].versions![0].size).toBeUndefined();
  for (const malformed of [
    { ...input, apps: null },
    { ...input, apps: [null] },
    { ...input, apps: [{ ...input.apps[0], versions: [{ version: null }] }] },
    { ...input, apps: [{ ...input.apps[0], versions: [null] }] },
    { ...input, news: [{ identifier: 'news', title: 'News', caption: null }] },
  ])
    await expect(h.registry.snapshot(h.owner, h.source.id, malformed, [host])).rejects.toThrow(
      'UNSUPPORTED_ALTSTORE_SCHEMA',
    );
});

it('rejects a redirect host revoked by a same-content snapshot during preflight', async () => {
  const h = await setup();
  const redirectHost = 'redirect.example.invalid';
  const first = await h.registry.snapshot(h.owner, h.source.id, fixture(), [host, redirectHost]);
  const marker = reference(
    (await h.catalog.feed(h.owner, h.source.id)).repository.apps[0].downloadURL!,
  );
  let closed = false;
  const catalog = new FeatherCatalog(h.db, h.registry, {
    now: h.now,
    fetch: async (url, options) => {
      const response = await fetchSafeStream(url, {
        ...options,
        resolve: async () => [{ address: '93.184.216.34', family: 4 }],
        transport: async (target): Promise<Response> =>
          target.hostname === host
            ? {
                status: 302,
                headers: { location: `https://${redirectHost}/final.ipa` },
                body: (async function* () {})(),
              }
            : { status: 200, headers: {}, body: (async function* () {})() },
      });
      const current = await h.registry.snapshot(h.owner, h.source.id, fixture(), [host]);
      expect(current.snapshot).toBe(first.snapshot);
      return {
        ...response,
        close: async () => {
          closed = true;
          await response.close();
        },
      };
    },
  });
  await expect(catalog.download(h.owner, marker)).rejects.toThrow('ARTIFACT_HOST_NOT_APPROVED');
  expect(closed).toBe(true);
});

it('omits malformed optional app and news dates before the repository reaches Swift', async () => {
  for (const malformed of ['', 'not-a-date', '2026-02-31', '10/31/2026']) {
    const input = fixture();
    const h = await setup({
      ...input,
      apps: input.apps.map((app) => ({ ...app, versionDate: malformed, date: malformed })),
      news: input.news.map((news) => ({ ...news, date: malformed })),
    });
    await h.registry.refresh(h.owner, h.source.id);
    const feed = await h.catalog.feed(h.owner, h.source.id);
    expect(feed.repository.apps[0].versionDate, malformed).toBeUndefined();
    expect(feed.repository.apps[0].date, malformed).toBeUndefined();
    expect(feed.repository.news![0].date, malformed).toBeUndefined();
  }
});

it('preserves Swift-supported numeric, ISO, date-only and legacy date forms', async () => {
  const dates = [
    1700000000,
    -123.5,
    '1700000000.5',
    '-1.5e2',
    ' 2026-10-31 ',
    '2026-10-31T09:08:07Z',
    '2026-10-31T09:08:07.123+03:00',
    '2026-10-31T09:08:07.123+0300',
    '2026-10-31T09:08:07+0300',
    '2026-10-31T09:08:07',
    '2026-10-31T09:08',
    '2026-10-31 09:08:07',
    'Tue, 14 Nov 2023 22:13:20 GMT',
    'Tue Nov 14 22:13:20 +0000 2023',
  ];
  const input = fixture();
  const h = await setup({
    ...input,
    apps: dates.map((date, index) => ({
      ...input.apps[0],
      bundleIdentifier: `com.example.date${index}`,
      versionDate: date,
      date,
    })),
    news: dates.map((date, index) => ({ ...input.news[0], identifier: `news-${index}`, date })),
  });
  await h.registry.refresh(h.owner, h.source.id);
  const feed = await h.catalog.feed(h.owner, h.source.id);
  const expected = dates.map((date) => (typeof date === 'string' ? date.trim() : date));
  expect(feed.repository.apps.map((app) => app.versionDate)).toEqual(expected);
  expect(feed.repository.apps.map((app) => app.date)).toEqual(expected);
  expect(feed.repository.news!.map((news) => news.date)).toEqual(expected);
});
