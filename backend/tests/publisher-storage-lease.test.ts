import { expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDatabase } from './helpers/database';
import { ownAuthority } from './helpers/seed-authority';
import { PersonalObjects, PersonalArtifacts } from '../packages/core/src/library/personal-storage';
import { Publisher, digest, type VerifiedReport } from '../packages/core/src/signing/publisher';
for (const loseStorage of [false, true])
  it(`publisher confirms real local bytes before committing (storage loss=${loseStorage})`, async () => {
    const db = await createDatabase(),
      directory = await mkdtemp(join(tmpdir(), 'isign-publish-'));
    try {
      await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','owner',0)");
      await db.query(
        "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','TEAM123','ready','asc')",
      );
      await db.query(
        "INSERT INTO devices(id,owner_id,connection_id,name,status,connection_generation,enrollment_verified_at) VALUES('d','o','c','Phone','ready',1,1)",
      );
      await db.query(
        "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','App.ipa','source',1,'source-digest','uploaded',0,999999)",
      );
      await db.query(
        "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_generation,state,idempotency_key,lease_token,lease_expires,created_at,updated_at) VALUES('j','o','u','d','c',1,'verifying','key','lease',999999,0,0)",
      );
      await ownAuthority(db);
      const objects = new PersonalObjects(db, directory, () => 10000, {
        maxFile: 1024,
        ownerQuota: 8192,
        globalQuota: 16384,
        minimumFree: 0,
        retentionMs: 86400000,
      });
      await objects.recover();
      const artifacts = new PersonalArtifacts(objects);
      await artifacts.reserveJob('o', 'j');
      const publisher = new Publisher(
        db,
        {
          put: async (key, body, owner) => {
            const stored = await artifacts.put(key, body, owner);
            if (loseStorage)
              await db.query("UPDATE personal_objects SET state='deleting' WHERE object_key=$1", [
                key,
              ]);
            return stored;
          },
          delete: artifacts.delete.bind(artifacts),
          confirmStored: artifacts.confirmStored.bind(artifacts),
        },
        { verify: async () => true },
        () => 10000,
      );
      const grant = await publisher.grant(
        'o',
        'j',
        'lease',
        'synthetic-vm',
        digest(Buffer.from('plan')),
      );
      const bytes = Buffer.from('synthetic artifact');
      const report: VerifiedReport = {
        ...grant,
        artifactDigest: digest(bytes),
        bundleId: 'test.fixture',
        version: '1',
        title: 'Fixture',
        certificateExpiresAt: 999999,
        profileExpiresAt: 999999,
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
      async function* stream() {
        yield bytes;
      }
      if (loseStorage) {
        await expect(publisher.publish(report, 'fixture', stream())).rejects.toThrow(
          'ARTIFACT_STORAGE_LEASE_EXPIRED',
        );
        expect((await db.query('SELECT id FROM artifacts')).rows).toHaveLength(0);
        expect((await db.query('SELECT id FROM personal_objects')).rows).toHaveLength(0);
      } else {
        const published = await publisher.publish(report, 'fixture', stream());
        expect(published.id).toBeTruthy();
        expect((await db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'ready' }]);
      }
    } finally {
      await db.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
