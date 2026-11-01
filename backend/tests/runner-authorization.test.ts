import { queuedJobFixture } from './helpers/job';
import { ownAuthority } from './helpers/seed-authority';
import { bindOwnFixture } from './helpers/login';
import { loginFixture, connectionFixture, deviceFixture } from './helpers/login';
import { it, expect } from 'vitest';
import { createHmac } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { token } from '../packages/core/src/shared/index';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';
import { RunnerAuthorization } from '../packages/core/src/signing/runner-authorization';
import { canonicalReport } from '../packages/core/src/shared/canonical-json';

it('keeps signed authorization within the runner TTL when the clock advances between reads', async () => {
  const db = await createDatabase();
  try {
    let clock = 10000;
    const key = Buffer.alloc(32, 8);
    await bindOwnFixture(db);
    await ownAuthority(db);
    const auth = new RunnerAuthorization(db, () => clock++, 'test', key);
    const result = await auth.authorize({
      operation: 'capabilities',
      binding: { nonce: token() },
      nonce: token(),
      audience: 'test',
    });
    expect(result.report.authorized).toBe(true);
    expect(result.report.checkedAt).toBe(10000);
    expect(result.report.expiresAt).toBe(25000);
    expect(result.report.expiresAt - result.report.checkedAt).toBeLessThanOrEqual(15000);
    expect(result.attestation).toBe(
      createHmac('sha256', key).update(canonicalReport(result.report)).digest('hex'),
    );
  } finally {
    await db.close();
  }
});

it('authorizes only current jobs and permits cleanup after cancellation without reopening private data', async () => {
  const db = await createDatabase();
  try {
    const s = new JobLifecycle(db, () => 10000);
    const owner = (await loginFixture(s.db, 'worker@example.invalid', s.now)).ownerId;
    const c = await connectionFixture(s.db, owner, 'TEAM-WORKER');
    const d = await deviceFixture(s.db, owner, c.id, 'Fixture', '18.0');
    await db.query("UPDATE connections SET provider='asc' WHERE id=$1", [c.id]);
    await db.query(
      'UPDATE devices SET enrollment_verified_at=1,enrollment_cms_sha256=$2 WHERE id=$1',
      [d.id, 'a'.repeat(64)],
    );
    await db.query('UPDATE devices SET connection_generation=1 WHERE id=$1', [d.id]);
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('auth-u',$1,'synthetic.ipa','synthetic',1,'synthetic','uploaded',0,999999)",
      [owner],
    );
    const j = await queuedJobFixture(s, owner, 'auth-u', 'auth');
    await db.query(
      "UPDATE jobs SET state='analyzing',device_id=$2,connection_id=$3,connection_generation=1,lease_token='current',lease_expires=999999 WHERE id=$1",
      [j.id, d.id, c.id],
    );
    const key = Buffer.alloc(32, 8),
      a = new RunnerAuthorization(db, () => 10000, 'test', key),
      binding = { ownerId: owner, jobId: j.id };
    const result = await a.authorize({
      operation: 'source',
      binding,
      nonce: token(),
      audience: 'test',
    });
    expect(result.report.authorized).toBe(true);
    expect(result.attestation).toBe(
      createHmac('sha256', key).update(canonicalReport(result.report)).digest('hex'),
    );
    expect(
      (
        await a.authorize({
          operation: 'source',
          binding: { ...binding, leaseToken: 'old' },
          nonce: token(),
          audience: 'test',
        })
      ).report.authorized,
    ).toBe(false);
    await db.query("UPDATE jobs SET state='cancelled',lease_token=NULL WHERE id=$1", [j.id]);
    expect(
      (await a.authorize({ operation: 'instance', binding, nonce: token(), audience: 'test' }))
        .report.authorized,
    ).toBe(false);
    expect(
      (await a.authorize({ operation: 'destroy', binding, nonce: token(), audience: 'test' }))
        .report.authorized,
    ).toBe(true);
    await expect(
      a.authorize({ operation: 'source', binding, nonce: token(), audience: 'foreign' }),
    ).rejects.toThrow('RUNNER_AUTHORIZATION_INVALID');
  } finally {
    await db.close();
  }
});
