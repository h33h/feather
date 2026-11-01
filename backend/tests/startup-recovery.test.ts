import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { connectionFixture, deviceFixture, loginFixture } from './helpers/login';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';
import { CatalogRegistry } from '../packages/core/src/catalog/registry';
it('startup terminates interrupted receiving jobs while preserving queued jobs', async () => {
  const db = await createDatabase();
  try {
    const a = await loginFixture(db, 'a', 1000),
      b = await loginFixture(db, 'b', 1000);
    const devices = new Map<string, string>();
    for (const user of [a, b]) {
      const c = await connectionFixture(db, user.ownerId, user.ownerId);
      const device = await deviceFixture(db, user.ownerId, c.id, 'Phone', '18.0');
      devices.set(user.ownerId, device.id);
    }
    const queue = new JobLifecycle(db, () => 1000);
    const receiving = await queue.beginClientInstallation(a.ownerId, {
      deviceId: devices.get(a.ownerId)!,
      releaseSha256: 'a'.repeat(64),
      key: 'a',
    });
    const queued = await queue.beginClientInstallation(b.ownerId, {
      deviceId: devices.get(b.ownerId)!,
      releaseSha256: 'b'.repeat(64),
      key: 'b',
    });
    await db.query("UPDATE uploads SET status='ready',digest='hash',size=1 WHERE id=$1", [
      queued.uploadId,
    ]);
    await queue.completeSource(b.ownerId, queued.jobId);
    await queue.recoverReceiving();
    expect((await db.query('SELECT state FROM jobs WHERE id=$1', [receiving.jobId])).rows).toEqual([
      { state: 'failed' },
    ]);
    expect(
      (
        await db.query<{ delete_requested_at: number }>(
          'SELECT delete_requested_at FROM uploads WHERE id=$1',
          [receiving.uploadId],
        )
      ).rows[0].delete_requested_at,
    ).toBe(1000);
    expect((await db.query('SELECT state FROM jobs WHERE id=$1', [queued.jobId])).rows).toEqual([
      { state: 'queued' },
    ]);
  } finally {
    await db.close();
  }
});
it('creates built-in catalogs outside session reads and avoids duplicates', async () => {
  const db = await createDatabase();
  try {
    await loginFixture(db, 'a', 1000);
    await loginFixture(db, 'b', 1000);
    const catalogs = new CatalogRegistry(db, () => 1000);
    await catalogs.ensureBuiltIns();
    await catalogs.ensureBuiltIns();
    expect((await db.query('SELECT kind FROM sources')).rows).toEqual([
      { kind: 'iapps' },
      { kind: 'iapps' },
    ]);
  } finally {
    await db.close();
  }
});
