import { loginFixture, connectionFixture, deviceFixture } from './helpers/login';
import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';
it('lease fencing rejects old heartbeat after recovery', async () => {
  const db = await createDatabase();
  try {
    let now = 10000;
    const service = new JobLifecycle(db, () => now);
    const s = await loginFixture(service.db, 'queue@example.invalid', service.now);
    const connection = await connectionFixture(db, s.ownerId, 'ABCDEFGHIJ');
    await deviceFixture(db, s.ownerId, connection.id, 'Phone', '18.0');
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u',$1,'test.ipa','safe.ipa',1,'hash','uploaded',0,999999999)",
      [s.ownerId],
    );
    const j = await service.enqueue(s.ownerId, 'u', 'one');
    await db.query("UPDATE jobs SET state='queued' WHERE id=$1", [j.id]);
    const lease = await service.claim(j.id, s.ownerId);
    await expect(service.enqueue(s.ownerId, 'u', 'two')).rejects.toThrow('ACTIVE_JOB_EXISTS');
    now += 60001;
    await service.recoverLeases();
    await expect(service.heartbeat(j.id, s.ownerId, lease)).rejects.toThrow('LEASE_LOST');
    now += 5001;
    const next = await service.claim(j.id, s.ownerId);
    expect(next).not.toBe(lease);
    await expect(service.heartbeat(j.id, s.ownerId, lease)).rejects.toThrow('LEASE_LOST');
    await service.heartbeat(j.id, s.ownerId, next);
  } finally {
    await db.close();
  }
});
