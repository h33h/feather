import { storedSources, storedReleases } from './helpers/catalog';
import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { CatalogRegistry } from '../packages/core/src/catalog/registry';
const feed = {
  appRepositories: [
    {
      appName: 'Synthetic',
      appVersion: '1',
      appPackage: 'https://download.synthetic.invalid/file.ipa',
    },
  ],
};
it('publisher trust is explicit; discovery is bounded exact hosts with known GitHub redirects', async () => {
  const db = await createDatabase();
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('o','o@synthetic.invalid',0)",
    );
    const registry = new CatalogRegistry(
      db,
      () => 100,
      async () => Buffer.from(JSON.stringify(feed)),
    );
    await expect(
      registry.add('o', 'source', 'https://feed.synthetic.invalid/feed'),
    ).rejects.toThrow('SOURCE_TRUST_REQUIRED');
    const source = await registry.add(
      'o',
      'source',
      'https://feed.synthetic.invalid/feed',
      [],
      true,
    );
    await registry.refresh('o', source.id);
    const row = (
      await db.query<{ feed: { hosts: string[]; trust: string } }>(
        'SELECT feed FROM sources WHERE id=$1',
        [source.id],
      )
    ).rows[0];
    expect(row.feed).toMatchObject({ hosts: ['download.synthetic.invalid'], trust: 'publisher' });
    expect(row.feed.hosts).not.toContain('*');
    const result = (await storedReleases(db, 'o', source.id))[0];
    expect((await registry.selection('o', source.id, result.id, result.snapshot)).hosts).toEqual([
      'download.synthetic.invalid',
    ]);
  } finally {
    await db.close();
  }
});
it('singleflight spans requests, persistent lease spans registries, failures back off and keep last good snapshot', async () => {
  const db = await createDatabase();
  let now = 100,
    reads = 0,
    fail = false,
    release!: () => void;
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('o','o@synthetic.invalid',0)",
    );
    const fetch = async () => {
      reads++;
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      if (fail) throw Error('SYNTHETIC FAILURE');
      return Buffer.from(JSON.stringify(feed));
    };
    const registry = new CatalogRegistry(db, () => now, fetch),
      otherWorker = new CatalogRegistry(db, () => now, fetch),
      source = await registry.add('o', 'source', 'https://feed.synthetic.invalid/feed', [], true);
    const a = registry.refresh('o', source.id),
      b = registry.refresh('o', source.id);
    while (!release) await new Promise((resolve) => setTimeout(resolve, 1));
    await expect(otherWorker.refresh('o', source.id)).rejects.toThrow('SOURCE_REFRESH_RUNNING');
    release();
    await Promise.all([a, b]);
    expect(reads).toBe(1);
    const previous = await storedReleases(db, 'o', source.id);
    now += CatalogRegistry.refreshIntervalMs;
    fail = true;
    release = undefined as never;
    const failure = registry.refresh('o', source.id);
    while (!release) await new Promise((resolve) => setTimeout(resolve, 1));
    release();
    await expect(failure).rejects.toThrow('REMOTE_UNAVAILABLE');
    const state = (await storedSources(db, 'o'))[0];
    expect(state.refresh_failures).toBe(1);
    expect(state.next_refresh_at).toBe(now + 60000);
    expect(state.last_error).toBe('REMOTE_UNAVAILABLE');
    expect(await storedReleases(db, 'o', source.id)).toEqual(previous);
    await expect(registry.refresh('o', source.id)).rejects.toThrow('SOURCE_REFRESH_BACKOFF');
    expect(reads).toBe(2);
  } finally {
    await db.close();
  }
});
it('removed source cannot resurrect after an in-flight download', async () => {
  const db = await createDatabase();
  let release!: () => void;
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('o','o@synthetic.invalid',0)",
    );
    const registry = new CatalogRegistry(
        db,
        () => 100,
        async () => {
          await new Promise<void>((resolve) => {
            release = resolve;
          });
          return Buffer.from(JSON.stringify(feed));
        },
      ),
      source = await registry.add('o', 'source', 'https://feed.synthetic.invalid/feed', [], true);
    const pending = registry.refresh('o', source.id);
    while (!release) await new Promise((resolve) => setTimeout(resolve, 1));
    await registry.remove('o', source.id);
    release();
    await expect(pending).rejects.toThrow('SOURCE_DISABLED');
    expect((await storedSources(db, 'o'))[0].state).toBe('deleted');
    expect(await storedReleases(db, 'o', source.id)).toEqual([]);
  } finally {
    await db.close();
  }
});
it('unsafe manifest URL never becomes a discovered artifact host', async () => {
  const db = await createDatabase();
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('o','o@synthetic.invalid',0)",
    );
    const registry = new CatalogRegistry(
        db,
        () => 100,
        async () =>
          Buffer.from(
            JSON.stringify({
              appRepositories: [
                { ...feed.appRepositories[0], appPackage: 'https://169.254.169.254/latest' },
              ],
            }),
          ),
      ),
      source = await registry.add('o', 'source', 'https://feed.synthetic.invalid/feed', [], true);
    await expect(registry.refresh('o', source.id)).rejects.toThrow('SSRF_BLOCKED');
    expect(await storedReleases(db, 'o', source.id)).toEqual([]);
  } finally {
    await db.close();
  }
});

it('automatically replaces iApps releases when the encrypted publisher feed changes and retries after corruption', async () => {
  const { readFile } = await import('node:fs/promises');
  const original = await readFile(
    new URL('./fixtures/iapps-current-encrypted.json', import.meta.url),
  );
  const updated = await readFile(
    new URL('./fixtures/iapps-updated-encrypted.json', import.meta.url),
  );
  const db = await createDatabase();
  let now = 100;
  let bytes = original;
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('o','o@synthetic.invalid',0)",
    );
    const registry = new CatalogRegistry(
      db,
      () => now,
      async () => bytes,
    );
    await registry.ensureBuiltIn('o');
    const source = (await storedSources(db, 'o'))[0];
    await registry.refreshDue();
    expect(await storedReleases(db, 'o', source.id)).toHaveLength(1654);
    now += CatalogRegistry.refreshIntervalMs;
    bytes = updated;
    expect((await registry.refreshDue())[0].status).toBe('fulfilled');
    const releases = await storedReleases(db, 'o', source.id);
    expect(releases).toHaveLength(1);
    expect(releases[0].metadata).toMatchObject({
      name: 'Synthetic iApps refresh',
      version: '2.0',
      url: expect.stringMatching(/^https:/),
    });
    const corrupt = JSON.parse(updated.toString());
    corrupt.appRepositories = 'corrupted';
    bytes = Buffer.from(JSON.stringify(corrupt));
    now += CatalogRegistry.refreshIntervalMs;
    expect((await registry.refreshDue())[0].status).toBe('rejected');
    expect(await storedReleases(db, 'o', source.id)).toEqual(releases);
    expect((await storedSources(db, 'o'))[0]).toMatchObject({
      state: 'ready',
      refresh_failures: 1,
      last_error: 'GBOX_DECRYPT_FAILED',
    });
    expect(
      (await registry.selection('o', source.id, releases[0].id, releases[0].snapshot)).release
        .version,
    ).toBe('2.0');
    bytes = updated;
    now += 60000;
    expect((await registry.refreshDue())[0].status).toBe('fulfilled');
    expect((await storedSources(db, 'o'))[0]).toMatchObject({
      state: 'ready',
      refresh_failures: 0,
      last_error: null,
    });
  } finally {
    await db.close();
  }
});

it('respects iApps backoff, active leases and disabled sources', async () => {
  const db = await createDatabase();
  const now = 100;
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('o','o@synthetic.invalid',0)",
    );
    const registry = new CatalogRegistry(
      db,
      () => now,
      async () => {
        throw Error('must not fetch');
      },
    );
    await registry.ensureBuiltIn('o');
    const source = (await storedSources(db, 'o'))[0];
    for (const testCase of [
      { state: 'error', error: 'GBOX_DECRYPT_FAILED', lease: 0, failure: 'SOURCE_REFRESH_BACKOFF' },
      {
        state: 'error',
        error: 'GBOX_DECRYPT_FAILED',
        lease: now + 60000,
        failure: 'SOURCE_REFRESH_RUNNING',
      },
      { state: 'disabled', error: 'GBOX_DECRYPT_FAILED', lease: 0, failure: 'SOURCE_DISABLED' },
    ]) {
      await db.query(
        'UPDATE sources SET state=$2,last_error=$3,next_refresh_at=$4,refresh_lease_until=$5 WHERE id=$1',
        [source.id, testCase.state, testCase.error, now + 3600000, testCase.lease],
      );
      expect(await registry.refreshDue()).toEqual([]);
      await expect(registry.refresh('o', source.id)).rejects.toThrow(testCase.failure);
    }
  } finally {
    await db.close();
  }
});
it('manual refresh can update before the scheduled interval without bypassing the shared lease', async () => {
  const db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','owner',0)");
    let requests = 0;
    const registry = new CatalogRegistry(
      db,
      () => 100,
      async () => {
        requests++;
        return Buffer.from(JSON.stringify(feed));
      },
    );
    const source = await registry.add(
      'o',
      'Catalog',
      'https://feed.synthetic.invalid/feed',
      [],
      true,
    );
    await registry.refresh('o', source.id);
    await registry.refresh('o', source.id, true);
    expect(requests).toBe(2);
    await expect(registry.refresh('o', source.id)).rejects.toThrow('SOURCE_REFRESH_BACKOFF');
  } finally {
    await db.close();
  }
});
