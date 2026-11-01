import { bindOwnFixture } from './helpers/login';
import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { Vault, type Kms } from '../packages/core/src/apple/vault';
import { Publisher } from '../packages/core/src/signing/publisher';
import type { ExecutorGrant } from '../packages/core/src/shared/runner-contracts';
async function fixture() {
  const db = await createDatabase();
  let now = 10000;
  const uploadDigest = createHash('sha256').update('synthetic source').digest('hex');
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner@example.test',0)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('connection','owner','SYNTHETIC1','ready','asc')",
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_generation,name,status,enrollment_verified_at,enrollment_cms_sha256) VALUES('device','owner','connection',1,'Synthetic','ready',1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
  );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('upload','owner','synthetic.ipa','synthetic.ipa',1,$1,'uploaded',0,999999999)",
    [uploadDigest],
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_generation,state,idempotency_key,lease_token,lease_expires,created_at,updated_at) VALUES('job','owner','upload','device','connection',1,'provisioning','synthetic','synthetic-lease',999999999,0,0)",
  );
  let unwrapped: Buffer | undefined;
  let hook: (() => Promise<void>) | undefined;
  const key = Buffer.alloc(32, 7);
  const kms: Kms = {
    generate: async () => ({ plaintext: Buffer.from(key), wrapped: 'synthetic-wrapped-key' }),
    unwrap: vi.fn(async () => {
      unwrapped = Buffer.from(key);
      await hook?.();
      return unwrapped;
    }),
  };
  const vault = new Vault(db, kms, () => now);
  const secret = await vault.seal(
    'owner',
    'connection',
    'distribution-key',
    Buffer.from('synthetic private payload fixture'),
  );
  const p8 = await vault.seal('owner', 'connection', 'p8', Buffer.from('synthetic p8 fixture'));
  await bindOwnFixture(db);
  const publisher = new Publisher(
    db,
    { put: async () => ({ digest: 'unused', size: 1 }), delete: async () => {} },
    { verify: async () => false },
    () => now,
  );
  const grant = await publisher.grant(
    'owner',
    'job',
    'synthetic-lease',
    'synthetic-isolated-vm',
    undefined,
    999999999,
  );
  return {
    db,
    vault,
    kms,
    secret,
    p8,
    grant,
    unwrapped: () => unwrapped,
    hook: (value: () => Promise<void>) => {
      hook = value;
    },
    advance: (value: number) => {
      now += value;
    },
  };
}
describe('Vault encrypted job material delivery', () => {
  it('returns exact opaque ciphertext and only an AES key without decrypting private material', async () => {
    const f = await fixture();
    try {
      // Deliberately invalid GCM content with valid encoding proves this path does not decrypt it on the web host.
      const ciphertext = Buffer.from('synthetic opaque ciphertext').toString('base64'),
        tag = Buffer.alloc(16).toString('base64');
      await f.db.query('UPDATE secrets SET ciphertext=$2,tag=$3 WHERE id=$1', [
        f.secret,
        ciphertext,
        tag,
      ]);
      const result = await f.vault.prepareJobMaterial(f.grant, f.secret);
      expect(result.envelope).toMatchObject({
        owner: 'owner',
        connection: 'connection',
        purpose: 'distribution-key',
        secret: f.secret,
        generation: 1,
        ciphertext,
        tag,
        wrappedKey: 'synthetic-wrapped-key',
      });
      expect(result.envelope.aad).toBe(
        JSON.stringify({
          owner: 'owner',
          connection: 'connection',
          purpose: 'distribution-key',
          secret: f.secret,
        }),
      );
      expect(result.dataKey).toEqual(Buffer.alloc(32, 7));
      expect(f.kms.unwrap).toHaveBeenCalledTimes(1);
      result.dataKey.fill(0);
      expect(f.unwrapped()).toEqual(Buffer.alloc(32));
    } finally {
      await f.db.close();
    }
  });
  it('rejects changed owner/job/lease/device/source/nonce/instance binding and p8 before KMS', async () => {
    const f = await fixture();
    try {
      const changes: Partial<ExecutorGrant>[] = [
        { ownerId: 'foreign' },
        { jobId: 'foreign' },
        { leaseToken: 'stale' },
        { deviceId: 'foreign' },
        { connectionGeneration: 2 },
        { uploadDigest: '0'.repeat(64) },
        { taskNonce: 'stale' },
        { isolationInstanceId: 'different-vm' },
        { expiresAt: f.grant.expiresAt + 1 },
      ];
      for (const change of changes)
        await expect(
          f.vault.prepareJobMaterial({ ...f.grant, ...change }, f.secret),
        ).rejects.toThrow('SECRET_UNAVAILABLE');
      await expect(f.vault.prepareJobMaterial(f.grant, f.p8)).rejects.toThrow('SECRET_UNAVAILABLE');
      expect(f.kms.unwrap).not.toHaveBeenCalled();
    } finally {
      await f.db.close();
    }
  });
  it('rejects oversized ciphertext before KMS unwrap', async () => {
    const f = await fixture();
    try {
      await f.db.query('UPDATE secrets SET ciphertext=$2 WHERE id=$1', [
        f.secret,
        Buffer.alloc(65537).toString('base64'),
      ]);
      await expect(f.vault.prepareJobMaterial(f.grant, f.secret)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      expect(f.kms.unwrap).not.toHaveBeenCalled();
    } finally {
      await f.db.close();
    }
  });
  it('zeros AES keys when disconnect changes generation during asynchronous KMS unwrap', async () => {
    const f = await fixture();
    try {
      f.hook(async () => {
        await f.db.query(
          "UPDATE connections SET state='disconnected',generation=2 WHERE id='connection'",
        );
      });
      await expect(f.vault.prepareJobMaterial(f.grant, f.secret)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      expect(f.unwrapped()).toEqual(Buffer.alloc(32));
    } finally {
      await f.db.close();
    }
  });
  it('zeros AES keys when task consumption, cancellation or secret tombstone races delivery', async () => {
    for (const sql of [
      'UPDATE executor_tasks SET consumed=true',
      "UPDATE jobs SET state='cancelled',lease_token=NULL WHERE id='job'",
      'UPDATE secrets SET deleted_at=1',
      "UPDATE devices SET status='disabled' WHERE id='device'",
      "UPDATE executor_tasks SET binding=jsonb_set(binding,'{isolationInstanceId}','\"different-vm\"')",
    ]) {
      const f = await fixture();
      try {
        f.hook(async () => {
          await f.db.query(sql);
        });
        await expect(f.vault.prepareJobMaterial(f.grant, f.secret)).rejects.toThrow(
          'SECRET_UNAVAILABLE',
        );
        expect(f.unwrapped()).toEqual(Buffer.alloc(32));
      } finally {
        await f.db.close();
      }
    }
  });
  it('rechecks grant expiry after KMS', async () => {
    const f = await fixture();
    try {
      f.hook(async () => {
        f.advance(900001);
      });
      await expect(f.vault.prepareJobMaterial(f.grant, f.secret)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      expect(f.unwrapped()).toEqual(Buffer.alloc(32));
    } finally {
      await f.db.close();
    }
  });
});
