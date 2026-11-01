import { afterEach, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createDatabase } from './helpers/database';
import { JobsActions } from '../packages/core/src/signing/jobs-actions';
import { CatalogRegistry } from '../packages/core/src/catalog/registry';
import { Importer } from '../packages/core/src/catalog/importer';
import { PersonalObjects, PersonalStorage } from '../packages/core/src/library/personal-storage';
const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});
it('admits before download, binds selected provenance and replays the same operation without downloading again', async () => {
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1)");
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,selected,connection_generation,enrollment_verified_at) VALUES('d','o','c','o','Phone','ready',true,1,1)",
  );
  const dir = await mkdtemp(path.join(tmpdir(), 'isign-import-test-'));
  directories.push(dir);
  const objects = new PersonalObjects(db, dir, () => 1000, {
    maxFile: 1024,
    ownerQuota: 8192,
    globalQuota: 16384,
    minimumFree: 0,
    retentionMs: 86400000,
  });
  await objects.recover();
  const catalogs = new CatalogRegistry(db, () => 1000);
  const source = await catalogs.add('o', 'Catalog', 'https://files.example.test/feed.json', [
    'files.example.test',
  ]);
  await catalogs.snapshot(
    'o',
    source.id,
    {
      appRepositories: [
        {
          appName: 'Synthetic',
          appVersion: '1.0',
          appPackage: 'https://files.example.test/app.ipa',
        },
      ],
    },
    ['files.example.test'],
  );
  const release = (await catalogs.releases('o', source.id))[0];
  let transfers = 0;
  const importer = new Importer(
    db,
    catalogs,
    new PersonalStorage(objects),
    new JobsActions(db, () => 1000),
    async () => {
      expect((await db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'receiving' }]);
      transfers++;
      return {
        body: (async function* () {
          yield Buffer.from('source');
        })(),
        finalOrigin: 'https://files.example.test',
      };
    },
  );
  const first = await importer.run('o', source.id, release.id, release.snapshot, undefined, {
    key: 'first',
  });
  expect((await db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'queued' }]);
  expect(
    await importer.run('o', source.id, release.id, release.snapshot, undefined, { key: 'first' }),
  ).toEqual(first);
  expect(transfers).toBe(1);
  expect(
    (await db.query<{ provenance: unknown }>('SELECT provenance FROM uploads')).rows[0].provenance,
  ).toMatchObject({ sourceId: source.id, sourceName: 'Catalog', selectedVersion: '1.0' });
  await expect(
    importer.run('foreign', source.id, release.id, release.snapshot, undefined, { key: 'other' }),
  ).rejects.toThrow('NOT_FOUND');
});
