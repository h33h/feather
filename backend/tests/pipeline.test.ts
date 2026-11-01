import { ownAuthority } from './helpers/seed-authority';
import { bindOwnFixture } from './helpers/login';
import { it, expect, vi } from 'vitest';
import { createDatabase } from './helpers/database';
import { hash, Failure } from '../packages/core/src/shared/index';
import { Service } from '../packages/core/src/application/service';
import { Publisher, digest, type VerifiedReport } from '../packages/core/src/signing/publisher';
import { MappingService } from '../packages/core/src/signing/mapping';
import { PipelineCoordinator, type AnalysisVm } from '../packages/core/src/signing/pipeline';
import { Readable } from 'node:stream';
import type { Component } from '../packages/core/src/signing/policy';
for (const mode of [
  'ready',
  'busy',
  'consent',
  'wrong-binding',
  'wrong-hash',
  'wrong-device',
  'unsupported-entitlement',
  'old-os',
  'unknown-os',
  'build-os',
  'unknown-os-wrong-binding',
  'build-os-wrong-binding',
  'missing-material-os',
  'ttl',
  'expired-vm',
  'cancel',
  'network-error',
  'standalone-dylib',
] as const)
  it('pipeline synthetic ' + mode, async () => {
    const db = await createDatabase();
    let destroyed = false;
    let clock = 100;
    const logs: string[] = [];
    const logger = vi.spyOn(console, 'error').mockImplementation((line) => logs.push(line));
    try {
      await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','f@a.b',0)");
      await db.query(
        "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
      );
      await db.query(
        "INSERT INTO devices(id,owner_id,connection_id,name,status,os_version,enrollment_verified_at,enrollment_cms_sha256) VALUES('d','o','c','Fixture','ready','18.0',1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
      );
      await db.query(
        "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','fixture.ipa','opaque',1,$1,'uploaded',0,999999)",
        [hash('source')],
      );
      await db.query("UPDATE devices SET udid=$1,connection_generation=1 WHERE id='d'", [
        'a'.repeat(40),
      ]);
      const service = new Service(db, { now: () => clock });
      if (
        mode === 'unknown-os' ||
        mode === 'unknown-os-wrong-binding' ||
        mode === 'missing-material-os'
      )
        await db.query("UPDATE devices SET os_version=NULL WHERE id='d'");
      if (mode === 'build-os' || mode === 'build-os-wrong-binding')
        await db.query("UPDATE devices SET os_version='23A345' WHERE id='d'");
      await ownAuthority(db);
      const job = await service.enqueue('o', 'u', 'synthetic');
      await db.query(
        "UPDATE jobs SET state='queued',connection_id='c',connection_generation=1 WHERE id=$1",
        [job.id],
      );
      const bytes = Buffer.from('synthetic artifact');
      await bindOwnFixture(db);
      await ownAuthority(db);
      const publisher = new Publisher(
        db,
        {
          put: async (_k, body) => {
            for await (const _c of body) {
              void _c;
            }
            expect(destroyed).toBe(true);
            expect(
              (
                await db.query<{ state: string }>("SELECT state FROM jobs WHERE id='j' OR id=$1", [
                  job.id,
                ])
              ).rows[0].state,
            ).toBe('verifying');
            return { digest: digest(bytes), size: bytes.length };
          },
          delete: async () => {},
        },
        { verify: async () => true },
        () => clock,
      );
      const components: Component[] = [
        {
          kind: 'app' as const,
          path: 'Payload/Fixture.app',
          bundleId: 'test.fixture',
          platform: 'ios',
          architectures: ['arm64'],
          encrypted: false,
          entitlements:
            mode === 'unsupported-entitlement'
              ? { 'com.apple.developer.icloud-services': ['CloudKit'] }
              : {},
          minOs: mode === 'old-os' ? '19.0' : '17.0',
        },
      ];
      const libraryPath = 'Payload/Fixture.app/Frameworks/libFixture.dylib';
      const libraryId = 'isign.dylib.' + hash(libraryPath);
      if (mode === 'standalone-dylib')
        components.push({
          ...components[0],
          kind: 'dylib',
          path: libraryPath,
          bundleId: libraryId,
          entitlements: {},
        });
      const vm: AnalysisVm = {
        id: 'fixture-vm',
        expiresAt: mode === 'expired-vm' ? 99 : 1100,
        destroy: async () => {
          destroyed = true;
        },
        analyze: async ({ grant }) => {
          if (mode === 'network-error')
            throw new TypeError('fetch failed', {
              cause: Object.assign(new Error('other side closed'), { code: 'UND_ERR_SOCKET' }),
            });
          expect(grant.expiresAt).toBe(1100);
          if (mode === 'cancel')
            await db.query("UPDATE jobs SET state='cancelled',lease_token=NULL WHERE id=$1", [
              job.id,
            ]);
          return {
            report: {
              ...grant,
              ...(mode === 'wrong-binding' ? { connectionGeneration: 2 } : {}),
              protocolVersion: 1,
              operation: 'analysis',
              executionAuthorized: false,
              analysis: {
                sha256: mode === 'wrong-hash' ? hash('other') : grant.uploadDigest,
                bundleId: 'test.fixture',
                version: '1.0',
                title: 'Fixture',
                components,
              },
            },
            attestation: 'synthetic',
          };
        },
        execute: async ({ grant, task }) => {
          if (mode === 'standalone-dylib') {
            const plan = task as {
              components: Array<{
                kind: string;
                bundleId: string;
                profileRequired: boolean;
                entitlements: unknown;
              }>;
              profiles: Record<string, unknown>;
            };
            expect(plan.components[0]).toMatchObject({
              kind: 'dylib',
              bundleId: libraryId,
              profileRequired: false,
              entitlements: {},
            });
            expect(Object.keys(plan.profiles)).toEqual(['test.fixture']);
          }
          expect(grant.expiresAt).toBe(1100);
          expect(grant.expiresAt).toBeGreaterThan(clock);
          return {
            report: {
              ...grant,
              artifactDigest: digest(bytes),
              bundleId: 'test.fixture',
              version: '1.0',
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
            } as VerifiedReport,
            attestation: 'synthetic',
            body: (async function* () {
              yield bytes;
            })(),
          };
        },
      };
      const pipeline = new PipelineCoordinator({
        now: () => clock,
        db,
        service,
        publisher,
        mapping: new MappingService(db),
        provider: {
          launch: async () => {
            if (mode === 'busy') throw new Failure('RUNNER_BUSY', 409);
            return vm;
          },
          verifyInstance: async () => true,
        },
        attestor: { verify: async () => true },
        storage: {
          read: async () => ({
            stat: async () => ({ size: 1 }),
            createReadStream: () => Readable.from([Buffer.from('source')]),
            close: async () => {},
          }),
          upload: async () => {
            throw Error();
          },
          recoverInterrupted: async () => {},
          cleanup: async () => {},
        },
        canPreserve: async () => {
          if (mode === 'old-os') throw Error('must not reach provisioning control');
          return mode !== 'consent';
        },
        provision: async ({ targets }) => {
          if (mode === 'ttl') clock += 500;
          return {
            identity: {
              ownerId: 'o',
              teamId: 'ABCDEFGHIJ',
              prefix: 'ABCDEFGHIJ',
              fingerprint: 'A'.repeat(40),
              expiresAt: 999999,
              materialPath: 'materials/key.p12',
            },
            profiles: {
              [targets['test.fixture']]: {
                ownerId: 'o',
                teamId: 'ABCDEFGHIJ',
                prefix: 'ABCDEFGHIJ',
                fingerprint: 'A'.repeat(40),
                expiresAt: 999999,
                bundleId: targets['test.fixture'],
                udids: ['a'.repeat(40)],
                entitlements: {
                  'application-identifier': 'ABCDEFGHIJ.' + targets['test.fixture'],
                  'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
                  'get-task-allow': false,
                },
                materialPath: 'materials/profile.mobileprovision',
              },
            },
            udid: mode === 'wrong-device' ? 'b'.repeat(40) : 'a'.repeat(40),
            deviceOs:
              mode === 'unknown-os'
                ? null
                : mode === 'missing-material-os'
                  ? undefined
                  : mode === 'build-os'
                    ? '23A345'
                    : mode === 'build-os-wrong-binding'
                      ? null
                      : '18.0',
          };
        },
      });
      if (mode === 'busy') {
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow('RUNNER_BUSY');
        expect(
          (await db.query('SELECT state,attempts FROM jobs WHERE id=$1', [job.id])).rows,
        ).toEqual([{ state: 'queued', attempts: 0 }]);
      } else if (mode === 'network-error') {
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow('fetch failed');
        const entry = logs
          .map((line) => JSON.parse(line))
          .find((log) => log.event === 'signing_pipeline_failed');
        expect(entry).toMatchObject({
          jobId: job.id,
          stage: 'analyze',
          instanceId: 'fixture-vm',
          error: { name: 'TypeError', message: 'fetch failed', cause: { code: 'UND_ERR_SOCKET' } },
        });
        expect(
          (
            await db.query<{ state: string; reason: string }>(
              'SELECT state,reason FROM jobs WHERE id=$1',
              [job.id],
            )
          ).rows[0],
        ).toEqual({ state: 'failed', reason: 'PIPELINE_FAILED' });
      } else if (mode === 'expired-vm')
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow(
          'EXECUTOR_INSTANCE_EXPIRED',
        );
      else if (mode === 'wrong-binding')
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow(
          'EXECUTOR_BINDING_MISMATCH',
        );
      else if (mode === 'wrong-hash')
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow('ANALYSIS_REPORT_INVALID');
      else if (mode === 'old-os')
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow('DEVICE_OS_TOO_OLD');
      else if (
        mode === 'wrong-device' ||
        mode === 'unknown-os-wrong-binding' ||
        mode === 'build-os-wrong-binding'
      )
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow(
          'MATERIAL_DEVICE_MISMATCH',
        );
      else if (mode === 'cancel')
        await expect(pipeline.kickoff('o', job.id, 'd')).rejects.toThrow('STALE_EXECUTOR_LEASE');
      else {
        await pipeline.kickoff('o', job.id, 'd');
        expect(
          (await db.query<{ state: string }>('SELECT state FROM jobs WHERE id=$1', [job.id]))
            .rows[0].state,
        ).toBe('ready');
      }
      expect(destroyed).toBe(mode !== 'busy');
    } finally {
      logger.mockRestore();
      await db.close();
    }
  });
