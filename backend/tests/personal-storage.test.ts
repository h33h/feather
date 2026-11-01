import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from 'vitest';
import { createDatabase } from './helpers/database';
import { PersonalArtifacts, PersonalObjects } from '../packages/core/src/library/personal-storage';
async function* bytes(n: number) {
  yield Buffer.alloc(n, 1);
}
test('physical files and output reservations count against quotas until cleanup', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'isign-quota-')),
    db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('a','a',0),('b','b',0)");
    const objects = new PersonalObjects(db, dir, () => 1000, {
      maxFile: 10,
      ownerQuota: 20,
      globalQuota: 30,
      minimumFree: 0,
      retentionMs: 100,
    });
    await objects.recover();
    const object = await objects.reserve('a', 'upload');
    await objects.write(
      object,
      'a',
      'upload',
      'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa',
      bytes(10),
    );
    const output = await objects.reserve('a', 'artifact', 'job');
    await expect(objects.reserve('a', 'upload')).rejects.toThrow('QUOTA_EXCEEDED');
    await objects.expireObject(object, 'upload', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa');
    await objects.remove(output);
    const next = await objects.reserve('a', 'upload');
    expect(next).toBeTruthy();
  } finally {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});
test('expiration interrupts a paused file handle before releasing quota', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'isign-open-')),
    db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('a','a',0)");
    const objects = new PersonalObjects(db, dir, () => 1000, {
      maxFile: 10,
      ownerQuota: 10,
      globalQuota: 10,
      minimumFree: 0,
      retentionMs: 100,
    });
    await objects.recover();
    const object = await objects.reserve('a', 'upload');
    await objects.write(
      object,
      'a',
      'upload',
      'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa',
      bytes(10),
    );
    const handle = await objects.handle(
      'upload',
      'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa',
      async () => {},
    );
    const stream = handle.createReadStream({ autoClose: false });
    stream.on('error', () => {});
    stream.pause();
    await expect(objects.reserve('a', 'upload')).rejects.toThrow('QUOTA_EXCEEDED');
    await objects.expireObject(object, 'upload', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa');
    expect(stream.destroyed).toBe(true);
    await expect(handle.stat()).rejects.toThrow();
    await handle.close();
    await handle.close();
    expect((await db.query('SELECT id FROM personal_objects')).rows).toHaveLength(0);
    expect(await objects.reserve('a', 'upload')).toBeTruthy();
  } finally {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});
test('account deletion aborts paused artifact writer before releasing physical quota', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'personal-writer-')),
    db = await createDatabase();
  let release!: () => void, reached!: () => void;
  const paused = new Promise<void>((r) => {
      release = r;
    }),
    written = new Promise<void>((r) => {
      reached = r;
    });
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('a','a@example.invalid',0),('b','b@example.invalid',0)",
    );
    const objects = new PersonalObjects(db, dir, () => 1000, {
        maxFile: 10,
        ownerQuota: 10,
        globalQuota: 10,
        minimumFree: 0,
        retentionMs: 100,
      }),
      artifacts = new PersonalArtifacts(objects);
    await objects.recover();
    const reserved = await objects.reserve('a', 'artifact', 'j');
    async function* chunks() {
      yield Buffer.alloc(10);
      reached();
      await paused;
    }
    const write = objects.write(
      reserved,
      'a',
      'artifact',
      'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa',
      chunks(),
    );
    void write.catch(() => {});
    await written;
    await db.query("UPDATE users SET deleted_at=1 WHERE id='a'");
    await artifacts.cleanup();
    await expect(write).rejects.toThrow();
    expect((await db.query('SELECT size,state FROM personal_objects')).rows).toEqual([]);
    release();
    expect((await db.query('SELECT * FROM personal_objects')).rows).toHaveLength(0);
    await objects.reserve('b', 'upload');
  } finally {
    release?.();
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('artifact deadline closes paused ranges before releasing physical quota', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'personal-deadline-'));
  const db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('a','a@example.invalid',0)");
    const objects = new PersonalObjects(db, dir, () => 1000, {
      maxFile: 10,
      ownerQuota: 10,
      globalQuota: 10,
      minimumFree: 0,
      retentionMs: 100,
    });
    await objects.recover();
    const objectId = await objects.reserve('a', 'artifact', 'j');
    const key = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa';
    await objects.write(objectId, 'a', 'artifact', key, bytes(10));
    const handle = await objects.handle('artifact', key, async () => {});
    const stream = handle.createReadStream({ start: 0, end: 9, autoClose: false });
    stream.on('error', () => {});
    stream.pause();
    await objects.expireObject(objectId, 'artifact', key);
    expect(stream.destroyed).toBe(true);
    await expect(handle.stat()).rejects.toThrow('NOT_FOUND');
    expect((await db.query('SELECT * FROM personal_objects')).rows).toHaveLength(0);
    const { readdir } = await import('node:fs/promises');
    expect(await readdir(path.join(dir, 'artifact'))).toEqual([]);
  } finally {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('deadline interrupts a writer paused inside its upstream iterator', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'personal-write-deadline-')),
    db = await createDatabase();
  let release!: () => void, reached!: () => void;
  const pause = new Promise<void>((r) => {
      release = r;
    }),
    written = new Promise<void>((r) => {
      reached = r;
    });
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('a','a@example.invalid',0)");
    const objects = new PersonalObjects(db, dir, () => 1000, {
      maxFile: 10,
      ownerQuota: 10,
      globalQuota: 10,
      minimumFree: 0,
      retentionMs: 100,
    });
    await objects.recover();
    const objectId = await objects.reserve('a', 'artifact', 'j'),
      key = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa';
    async function* source() {
      yield Buffer.alloc(10);
      reached();
      await pause;
    }
    const writing = objects.write(objectId, 'a', 'artifact', key, source());
    void writing.catch(() => {});
    await written;
    await objects.expireObject(objectId, 'artifact', key);
    await expect(writing).rejects.toThrow('UPLOAD_INTERRUPTED');
    expect((await db.query('SELECT * FROM personal_objects')).rows).toHaveLength(0);
  } finally {
    release?.();
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('publication checks stored owner and exact byte count', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'personal-journal-')),
    db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('a','a@example.invalid',0)");
    const objects = new PersonalObjects(db, dir, () => 1000, {
      maxFile: 10,
      ownerQuota: 10,
      globalQuota: 10,
      minimumFree: 0,
      retentionMs: 100,
    });
    await objects.recover();
    const objectId = await objects.reserve('a', 'artifact', 'j'),
      key = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa';
    await objects.write(objectId, 'a', 'artifact', key, bytes(10));
    const artifacts = new PersonalArtifacts(objects);
    await artifacts.confirmStored(db, key, 'a', 10);
    await expect(artifacts.confirmStored(db, key, 'b', 10)).rejects.toThrow(
      'ARTIFACT_STORAGE_LEASE_EXPIRED',
    );
    await expect(artifacts.confirmStored(db, key, 'a', 11)).rejects.toThrow(
      'ARTIFACT_STORAGE_LEASE_EXPIRED',
    );
    expect(artifacts.retentionMs).toBe(1800000);
  } finally {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});
test('cleanup preserves active reserved and writing outputs; removes published output after connection fence', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'personal-active-output-')),
    db = await createDatabase();
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('a','synthetic-active@example.invalid',0)",
    );
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','a','TEAM','ready','mock')",
    );
    await db.query(
      "INSERT INTO devices(id,owner_id,connection_id,name,status) VALUES('d','a','c','Synthetic','ready')",
    );
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','a','Synthetic.ipa','input',1,'synthetic','uploaded',0,999999)",
    );
    await db.query(
      "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_generation,state,idempotency_key,created_at,updated_at) VALUES('j','a','u','d','c',1,'signing','synthetic',0,0)",
    );
    const objects = new PersonalObjects(db, dir, () => 100, {
        maxFile: 10,
        ownerQuota: 30,
        globalQuota: 30,
        minimumFree: 0,
        retentionMs: 10000,
      }),
      artifacts = new PersonalArtifacts(objects);
    await objects.recover();
    const objectId = await objects.reserve('a', 'artifact', 'j');
    await artifacts.cleanup();
    expect((await db.query('SELECT id,state FROM personal_objects')).rows).toEqual([
      { id: objectId, state: 'reserved' },
    ]);
    const key = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa.ipa';
    await objects.write(objectId, 'a', 'artifact', key, bytes(1));
    await db.query("UPDATE personal_objects SET state='writing' WHERE id=$1", [objectId]);
    await artifacts.cleanup();
    expect((await db.query('SELECT state FROM personal_objects')).rows).toEqual([
      { state: 'writing' },
    ]);
    await db.query("UPDATE personal_objects SET state='live' WHERE id=$1", [objectId]);
    await artifacts.cleanup();
    expect((await db.query('SELECT state FROM personal_objects')).rows).toEqual([
      { state: 'live' },
    ]);
    await artifacts.confirmStored(db, key, 'a', 1);
    await db.query("UPDATE jobs SET state='ready' WHERE id='j'");
    await db.query(
      "INSERT INTO artifacts(id,owner_id,job_id,connection_id,device_id,object_key,digest,metadata,valid_until,created_at,expires_at,verified) VALUES('a','a','j','c','d',$1,'synthetic',$2,999999,0,999999,true)",
      [key, JSON.stringify({ generation: 1 })],
    );
    await db.query("UPDATE artifacts SET expires_at=$1 WHERE id='a'", [
      100 + PersonalArtifacts.availabilityMs,
    ]);
    await db.query("UPDATE connections SET state='disconnected',generation=2 WHERE id='c'");
    await artifacts.cleanup();
    expect((await db.query('SELECT id FROM personal_objects')).rows).toHaveLength(0);
  } finally {
    await db.close();
    await rm(dir, { recursive: true, force: true });
  }
});
