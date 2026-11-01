import { loginFixture, connectionFixture, deviceFixture } from './helpers/login';
import { it, expect } from 'vitest';
import type { Database } from '../packages/core/src/shared/database';
import { createDatabase } from './helpers/database';
import { Service } from '../packages/core/src/application/service';
import { Publisher, digest, type VerifiedReport } from '../packages/core/src/signing/publisher';
it('publishes only bound attested verified bytes and fences disconnect and replay', async () => {
  const db = await createDatabase();
  try {
    let code = '';
    const now = () => 10000,
      s = new Service(db, {
        now,
      });
    const login = await loginFixture(s.db, 'publisher@example.invalid', s.now),
      owner = login.ownerId;
    const c = await connectionFixture(s.db, owner, 'TEAM-PUBLISH'),
      d = await deviceFixture(s.db, owner, c.id, 'Fixture', '27.0');
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('upload',$1,'fixture.ipa','source.ipa',1,'source-digest','uploaded',0,999999999)",
      [owner],
    );
    const job = await s.enqueue(owner, 'upload', 'publish');
    await db.query(
      "UPDATE jobs SET state='verifying',device_id=$2,lease_token='lease',lease_expires=999999 WHERE id=$1",
      [job.id, d.id],
    );
    const objects = new Map<string, Uint8Array>(),
      publisher = new Publisher(
        db,
        {
          put: async (key, body) => {
            const chunks = [];
            for await (const chunk of body) chunks.push(Buffer.from(chunk));
            const bytes = Buffer.concat(chunks);
            objects.set(key, bytes);
            return { digest: digest(bytes), size: bytes.length };
          },
          delete: async (key) => {
            objects.delete(key);
          },
        },
        { verify: async (_report, attestation) => attestation === 'synthetic-trusted-fixture' },
        now,
      );
    const grant = await publisher.grant(
      owner,
      job.id,
      'lease',
      'vm-synthetic-fixture',
      digest(Buffer.from('synthetic-approved-plan')),
    );
    const bytes = Buffer.from('synthetic signed result, no executable');
    const report: VerifiedReport = {
      ...grant,
      artifactDigest: digest(bytes),
      bundleId: 'test.fixture',
      version: '1',
      title: 'Fixture',
      certificateExpiresAt: 999999,
      profileExpiresAt: 888888,
      checks: {
        archive: true,
        components: true,
        signatures: true,
        profiles: true,
        device: true,
        entitlements: true,
        mapping: true,
      },
    };
    const stream = async function* () {
      yield bytes;
    };
    await expect(publisher.publish(report, 'wrong', stream())).rejects.toThrow(
      'EXECUTOR_ATTESTATION_INVALID',
    );
    await expect(
      publisher.publish(
        { ...report, connectionGeneration: 2 },
        'synthetic-trusted-fixture',
        stream(),
      ),
    ).rejects.toThrow('EXECUTOR_BINDING_MISMATCH');
    expect(objects.size).toBe(0);
    const commitFailDb: Database = {
      query: db.query.bind(db),
      close: async () => {},
      transaction: async (work) =>
        db.transaction(async (tx) => {
          await work(tx);
          throw new Error('synthetic commit failure');
        }),
    };
    let orphan = false;
    const failedPublisher = new Publisher(
      commitFailDb,
      {
        put: async () => {
          orphan = true;
          return { digest: report.artifactDigest, size: bytes.length };
        },
        delete: async () => {
          orphan = false;
        },
      },
      { verify: async () => true },
      now,
    );
    await expect(failedPublisher.publish(report, 'synthetic', stream())).rejects.toThrow(
      'synthetic commit failure',
    );
    expect(orphan).toBe(false);
    expect((await db.query('SELECT id FROM artifacts')).rows).toHaveLength(0);
    const a = await publisher.publish(report, 'synthetic-trusted-fixture', stream());
    expect(a.id).toBeTruthy();
    expect(objects.size).toBe(1);
    expect(
      (await db.query<{ state: string }>('SELECT state FROM jobs WHERE id=$1', [job.id])).rows[0]
        .state,
    ).toBe('ready');
    await expect(publisher.publish(report, 'synthetic-trusted-fixture', stream())).rejects.toThrow(
      'STALE_EXECUTOR_GRANT',
    );
    expect(objects.size).toBe(1);
    await db.query(
      "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('upload2',$1,'fixture.ipa','source2.ipa',1,'source-digest','uploaded',0,999999999)",
      [owner],
    );
    const job2 = await s.enqueue(owner, 'upload2', 'second');
    await db.query(
      "UPDATE jobs SET state='verifying',device_id=$2,lease_token='lease2',lease_expires=999999 WHERE id=$1",
      [job2.id, d.id],
    );
    const grant2 = await publisher.grant(
      owner,
      job2.id,
      'lease2',
      'vm-synthetic-fixture',
      digest(Buffer.from('synthetic-approved-plan')),
    );
    await s.disconnect(login.token, login.csrf, 'http://localhost:3000', 'http://localhost:3000');
    await expect(
      publisher.publish({ ...report, ...grant2 }, 'synthetic-trusted-fixture', stream()),
    ).rejects.toThrow('STALE_EXECUTOR_GRANT');
    expect(objects.size).toBe(1);
  } finally {
    await db.close();
  }
});
it('verifies canonical executor HMAC and refuses changed nonce', async () => {
  const { createHmac } = await import('node:crypto');
  const { HmacExecutorAttestor, canonicalReport } =
    await import('../packages/core/src/signing/publisher');
  const key = Buffer.alloc(32, 9),
    attestor = new HmacExecutorAttestor(key);
  const report = {
    ownerId: 'synthetic-owner',
    taskNonce: 'synthetic-nonce',
    title: 'Синтетический отчёт',
  } as VerifiedReport;
  const signature = createHmac('sha256', key).update(canonicalReport(report)).digest('hex');
  expect(await attestor.verify(report, signature)).toBe(true);
  expect(await attestor.verify({ ...report, taskNonce: 'changed' }, signature)).toBe(false);
  expect(await attestor.verify(report, 'invalid')).toBe(false);
  key.fill(0);
});
