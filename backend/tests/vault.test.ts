import { loginFixture, connectionFixture, deviceFixture } from './helpers/login';
import { it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';
import { Vault, type Kms } from '../packages/core/src/apple/vault';
it('envelope encryption never persists plaintext and requires current owner job lease', async () => {
  const db = await createDatabase();
  try {
    const now = 10000;
    const s = new JobLifecycle(db, () => now);
    const owner = (await loginFixture(s.db, 'vault@example.invalid', s.now)).ownerId;
    const c = await connectionFixture(s.db, owner, 'TEAM-VAULT');
    const keys = new Map<string, Buffer>();
    const kms: Kms = {
      generate: async () => {
        const plaintext = randomBytes(32);
        keys.set('test-wrapped-reference', Buffer.from(plaintext));
        return { plaintext, wrapped: 'test-wrapped-reference' };
      },
      unwrap: async (wrapped) => Buffer.from(keys.get(wrapped)!),
    };
    const vault = new Vault(db, kms, () => now);
    const secret = await vault.seal(
      owner,
      c.id,
      'p8',
      Buffer.from('synthetic-secret-never-real-key'),
    );
    expect(JSON.stringify((await db.query('SELECT * FROM secrets')).rows)).not.toContain(
      'synthetic-secret-never-real-key',
    );
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u',$1,'own.ipa','input.ipa',1,'hash','uploaded',0,999999999)",
      [owner],
    );
    const d = await deviceFixture(s.db, owner, c.id, 'Synthetic device', '18.0');
    const j = await s.enqueue(owner, 'u', 'one');
    await db.query(
      'UPDATE jobs SET connection_id=$2,connection_generation=1,device_id=$3 WHERE id=$1',
      [j.id, c.id, d.id],
    );
    await db.query("UPDATE jobs SET state='queued' WHERE id=$1", [j.id]);
    const lease = await s.claim(j.id, owner);
    await expect(vault.openForJob('foreign', secret, j.id, lease)).rejects.toThrow(
      'SECRET_UNAVAILABLE',
    );
    expect((await vault.openForJob(owner, secret, j.id, lease)).toString()).toBe(
      'synthetic-secret-never-real-key',
    );
    await expect(vault.openForJob(owner, secret, j.id, 'stale')).rejects.toThrow(
      'SECRET_UNAVAILABLE',
    );
    await vault.tombstone(owner, secret);
    await expect(vault.openForJob(owner, secret, j.id, lease)).rejects.toThrow(
      'SECRET_UNAVAILABLE',
    );
  } finally {
    await db.close();
  }
});
it('rechecks tombstone after asynchronous KMS unwrap and returns no stale secret', async () => {
  const db = await createDatabase();
  try {
    const s = new JobLifecycle(db, () => 10000);
    const owner = (await loginFixture(s.db, 'vault-race@example.invalid', s.now)).ownerId;
    const c = await connectionFixture(s.db, owner, 'TEAM-RACE');
    let key = Buffer.alloc(0);
    let release!: () => void;
    let started!: () => void;
    const ready = new Promise<void>((r) => {
      started = r;
    });
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const kms: Kms = {
      generate: async () => {
        key = randomBytes(32);
        return { plaintext: Buffer.from(key), wrapped: 'test-only' };
      },
      unwrap: async () => {
        const copy = Buffer.from(key);
        started();
        await gate;
        return copy;
      },
    };
    const vault = new Vault(db, kms, () => 10000);
    const secret = await vault.seal(owner, c.id, 'p8', Buffer.from('public synthetic secret'));
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u',$1,'own.ipa','input.ipa',1,'hash','uploaded',0,999999999)",
      [owner],
    );
    const d = await deviceFixture(s.db, owner, c.id, 'Synthetic device', '18.0');
    const j = await s.enqueue(owner, 'u', 'one');
    await db.query(
      'UPDATE jobs SET connection_id=$2,connection_generation=1,device_id=$3 WHERE id=$1',
      [j.id, c.id, d.id],
    );
    await db.query("UPDATE jobs SET state='queued' WHERE id=$1", [j.id]);
    const lease = await s.claim(j.id, owner);
    const pending = vault.openForJob(owner, secret, j.id, lease);
    const failed = pending.catch((e) => e);
    await ready;
    await vault.tombstone(owner, secret);
    release();
    expect((await failed).message).toBe('SECRET_UNAVAILABLE');
  } finally {
    await db.close();
  }
});
