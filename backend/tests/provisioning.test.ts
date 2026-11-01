import { SessionService } from '../packages/core/src/auth/sessions';
import { ConnectionLifecycle } from '../packages/core/src/apple/connection-lifecycle';
import { loginFixture, connectionFixture, deviceFixture } from './helpers/login';
import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { JobLifecycle } from '../packages/core/src/signing/job-lifecycle';
import { Publisher } from '../packages/core/src/signing/publisher';
import { Vault } from '../packages/core/src/apple/vault';
import { Provisioning, MutationUncertain } from '../packages/core/src/apple/provisioning';
it('persists private-key reference before certificate POST and reconciles uncertainty without retry', async () => {
  const db = await createDatabase();
  try {
    const now = () => 10000,
      s = new JobLifecycle(db, now);
    const login = await loginFixture(s.db, 'provision@example.invalid', s.now),
      owner = login.ownerId;
    const c = await connectionFixture(s.db, owner, 'TEAM-PROVISION'),
      d = await deviceFixture(s.db, owner, c.id, 'Fixture', '27.0');
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('upload',$1,'fixture.ipa','source.ipa',1,'source-digest','uploaded',0,999999999)",
      [owner],
    );
    const job = await s.enqueue(owner, 'upload', 'provision');
    await db.query(
      "UPDATE jobs SET state='provisioning',device_id=$2,lease_token='lease',lease_expires=999999 WHERE id=$1",
      [job.id, d.id],
    );
    const publisher = new Publisher(
        db,
        { put: async () => ({ size: 1, digest: 'test' }), delete: async () => {} },
        { verify: async () => false },
        now,
      ),
      grant = await publisher.grant(owner, job.id, 'lease', 'vm-synthetic', undefined, 999999999);
    let calls = 0,
      visible = false;
    const p = new Provisioning(
      db,
      {
        create: async () => {
          calls++;
          throw new MutationUncertain();
        },
        find: async () => (visible ? [{ id: 'own-synthetic-certificate' }] : []),
      },
      now,
    );
    await expect(p.ensure(grant, 'certificate', { csr: 'synthetic-public-csr' })).rejects.toThrow(
      'PRIVATE_KEY_NOT_PERSISTED',
    );
    expect(calls).toBe(0);
    const vault = new Vault(
      db,
      {
        generate: async () => ({
          plaintext: Buffer.alloc(32, 7),
          wrapped: 'synthetic-wrapped-key',
        }),
        unwrap: async () => Buffer.alloc(32, 7),
      },
      now,
    );
    const keyRef = await vault.seal(
      owner,
      c.id,
      'distribution-key',
      Buffer.from('synthetic fixture, not a real private key'),
    );
    await expect(
      p.ensure(grant, 'certificate', { csr: 'synthetic-public-csr' }, keyRef),
    ).rejects.toThrow('RESOURCE_RECONCILIATION_REQUIRED');
    expect(calls).toBe(1);
    await expect(
      p.ensure(grant, 'certificate', { csr: 'synthetic-public-csr' }, keyRef),
    ).rejects.toThrow('RESOURCE_RECONCILIATION_REQUIRED');
    expect(calls).toBe(1);
    visible = true;
    expect(await p.ensure(grant, 'certificate', { csr: 'synthetic-public-csr' }, keyRef)).toEqual({
      id: 'own-synthetic-certificate',
      reconciled: true,
    });
    expect(calls).toBe(1);
    await new ConnectionLifecycle(
      s.db,
      () => s.now,
      new SessionService(s.db, { now: () => s.now }),
    ).disconnect(login.token, login.csrf, 'http://localhost:3000', 'http://localhost:3000');
    await expect(p.ensure(grant, 'bundle', { identifier: 'test.fixture' })).rejects.toThrow(
      'STALE_EXECUTOR_LEASE',
    );
  } finally {
    await db.close();
  }
});
