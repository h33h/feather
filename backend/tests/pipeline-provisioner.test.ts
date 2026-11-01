import { ownAuthority } from './helpers/seed-authority';
import { bindOwnFixture } from './helpers/login';
import { AppleSharing } from '../packages/core/src/apple/access';
import { it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { ProductionProvisioner } from '../packages/core/src/signing/provisioner';
import { AppleProvisioningApi } from '../packages/core/src/apple/provisioning-client';
import { hash } from '../packages/core/src/shared/index';
import type { ExecutorGrant } from '../packages/core/src/shared/runner-contracts';
for (const mode of [
  'ready',
  'unknown-os',
  'build-os',
  'wrong-os',
  'wrong-device',
  'uncertain',
  'uncertain-committed',
  'profile-inactive',
  'shared-ready',
  'exact',
  'wildcard-existing',
  'preserve',
  'renewal',
  'scope-error',
  'scope-ambiguous',
] as const)
  it('actual resource planner synthetic ' + mode, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'isign-provisioner-fixture-'));
    let pem: string;
    try {
      execFileSync(
        'openssl',
        [
          'req',
          '-x509',
          '-newkey',
          'rsa:2048',
          '-nodes',
          '-keyout',
          join(directory, 'key'),
          '-out',
          join(directory, 'cert'),
          '-subj',
          '/CN=Synthetic fixture/OU=ABCDEFGHIJ',
          '-days',
          '1',
        ],
        { stdio: 'ignore' },
      );
      pem = readFileSync(join(directory, 'cert'), 'utf8');
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
    const cert = new X509Certificate(pem),
      db = await createDatabase();
    let now = Date.parse(cert.validFrom) + 1000;
    try {
      await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','fixture@b.c',0)");
      await db.query(
        "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
      );
      await ownAuthority(db);
      const principal = mode === 'shared-ready' ? 'recipient' : 'o';
      let shareId: string | undefined;
      if (mode === 'shared-ready') {
        await db.query(
          "INSERT INTO users(id,login_name,created_at) VALUES('recipient','recipient@synthetic.invalid',0)",
        );
        const sharing = new AppleSharing(db, () => now),
          profile = (
            await db.query<{ public_profile_id: string }>(
              "SELECT public_profile_id FROM users WHERE id='recipient'",
            )
          ).rows[0].public_profile_id,
          grant = await sharing.share('o', profile);

        shareId = grant.grantId;
      }
      await db.query(
        `INSERT INTO devices(id,owner_id,connection_id,name,status,os_version,udid,connection_generation,apple_resource_id,enrollment_verified_at,enrollment_cms_sha256) VALUES('d','${principal}','c','fixture','ready','18.0',$1,1,'apple-device',1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')`,
        ['a'.repeat(40)],
      );
      await db.query(
        "UPDATE devices SET connection_owner_id=$1,access_grant_id=$2,access_grant_generation=$3 WHERE id='d'",
        [mode === 'shared-ready' ? 'o' : principal, shareId ?? null, shareId ? 1 : null],
      );
      if (mode === 'unknown-os') await db.query("UPDATE devices SET os_version=NULL WHERE id='d'");
      if (mode === 'build-os')
        await db.query("UPDATE devices SET os_version='23A345' WHERE id='d'");
      await db.query(
        `INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','${principal}','fixture.ipa','opaque',1,$1,'uploaded',0,$2)`,
        [hash('source'), now + 100000],
      );
      await db.query(
        `INSERT INTO jobs(id,owner_id,upload_id,device_id,state,idempotency_key,created_at,updated_at,lease_token,lease_expires,connection_id,connection_generation) VALUES('j','${principal}','u','d','provisioning','fixture',0,0,'lease',$1,'c',1)`,
        [now + 100000],
      );
      await db.query(
        "INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag,generation) VALUES('s','o','c','distribution-key','wrapped','nonce','cipher','tag',1)",
      );
      await db.query(
        "INSERT INTO bootstrap_operations(owner_id,connection_id,generation,nonce,expires_at,identity,certificate_state,certificate) VALUES('o','c',1,'n',$1,$2,'committed',$3)",
        [
          now + 100000,
          JSON.stringify({
            secretRef: 's',
            spkiSha256: createHash('sha256')
              .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
              .digest('hex'),
          }),
          JSON.stringify({
            id: 'certificate',
            pem,
            teamId: 'ABCDEFGHIJ',
            expiresAt: Date.parse(cert.validTo),
          }),
        ],
      );
      await db.query(
        `INSERT INTO mappings(id,owner_id,connection_id,original_id,target_id) VALUES('mapping','${principal}','c','test.fixture','test.copy')`,
      );
      const grant: ExecutorGrant = {
        ownerId: principal,
        connectionOwnerId: 'o',
        ...(shareId ? { accessGrantId: shareId, accessGrantGeneration: 1 } : {}),
        jobId: 'j',
        leaseToken: 'lease',
        connectionId: 'c',
        connectionGeneration: 1,
        deviceId: 'd',
        uploadDigest: hash('source'),
        taskNonce: 'nonce',
        isolationInstanceId: 'vm',
        expiresAt: now + 100000,
      };
      const bundles: { id: string; type: string; attributes: Record<string, unknown> }[] = [],
        profiles: {
          id: string;
          type: string;
          attributes: Record<string, unknown>;
          relationships: Record<string, unknown>;
        }[] = [];
      if (mode === 'exact') {
        for (const identifier of ['test.copy', 'test.copy.widget'])
          bundles.push({ id: identifier, type: 'bundleIds', attributes: { identifier } });
      }
      if (mode === 'wildcard-existing' || mode === 'renewal')
        bundles.push({ id: 'wildcard', type: 'bundleIds', attributes: { identifier: '*' } });
      if (mode === 'scope-ambiguous') {
        for (let i = 0; i < 2; i++)
          bundles.push({
            id: 'exact-' + i,
            type: 'bundleIds',
            attributes: { identifier: 'test.copy' },
          });
      }
      if (mode === 'preserve')
        await db.query("UPDATE mappings SET target_id=original_id WHERE id='mapping'");
      let posts = 0;
      let apiCalls = 0;
      const api = new AppleProvisioningApi(
        {
          request: async (method, path, body) => {
            apiCalls++;
            if (path.startsWith('/v1/certificates'))
              return {
                data: [
                  {
                    id: 'certificate',
                    type: 'certificates',
                    attributes: { certificateContent: Buffer.from(pem).toString('base64') },
                  },
                ],
              };
            if (path.startsWith('/v1/devices'))
              return {
                data: [
                  {
                    id: 'apple-device',
                    type: 'devices',
                    attributes: { udid: 'a'.repeat(40), status: 'ENABLED' },
                  },
                ],
              };
            if (mode === 'scope-error' && path.startsWith('/v1/bundleIds'))
              throw Error('synthetic permission failure');
            if (method === 'GET' && path.startsWith('/v1/bundleIds'))
              return {
                data: bundles.filter(
                  (row) =>
                    row.attributes.identifier ===
                    new URL(path, 'https://a').searchParams.get('filter[identifier]'),
                ),
              };
            if (method === 'GET' && path.startsWith('/v1/profiles'))
              return {
                data: profiles.filter(
                  (row) =>
                    row.attributes.name ===
                    new URL(path, 'https://a').searchParams.get('filter[name]'),
                ),
              };
            const value = body as {
              data: { attributes: Record<string, unknown>; relationships: Record<string, unknown> };
            };
            posts++;
            if (path === '/v1/bundleIds') {
              const row = {
                id: 'bundle-' + bundles.length,
                type: 'bundleIds',
                attributes: value.data.attributes,
              };
              bundles.push(row);
              return { data: row };
            }
            if (path === '/v1/profiles') {
              if (mode === 'uncertain') throw Error('synthetic timeout');
              const row = {
                id: 'profile-' + profiles.length,
                type: 'profiles',
                attributes: {
                  ...value.data.attributes,
                  profileState: mode === 'profile-inactive' ? 'INVALID' : 'ACTIVE',
                  expirationDate: cert.validTo,
                  profileContent: Buffer.from('opaque synthetic CMS').toString('base64'),
                },
                relationships: value.data.relationships,
              };
              profiles.push(row);
              if (mode === 'uncertain-committed') throw Error('synthetic timeout after mutation');
              return { data: row };
            }
            throw Error('unexpected route');
          },
        },
        () => now,
      );
      const dataKey = Buffer.alloc(32, 7);
      await bindOwnFixture(db);
      const planner = new ProductionProvisioner({
        db,
        api: async () => api,
        now: () => now,
        vault: {
          prepareJobMaterial: async () => ({
            envelope: {
              owner: 'o',
              connection: 'c',
              purpose: 'distribution-key',
              secret: 's',
              aad: 'a',
              wrappedKey: 'w',
              nonce: 'n',
              ciphertext: 'c',
              tag: 't',
              generation: 1,
            },
            dataKey,
          }),
        },
        rpc: {
          call: async <T>(_operation: string, binding: ExecutorGrant, payload: unknown) => {
            expect(binding).toEqual(grant);
            const p = payload as {
              profiles: { bundleId: string; cmsSha256: string }[];
              expected: { fingerprint: string; deviceOs: string | null };
            };
            expect(p.expected.fingerprint).toMatch(/^[A-F0-9]{40}$/);
            if (mode !== 'exact') {
              expect(p.profiles[0].cmsSha256).toMatch(/^[a-f0-9]{64}$/);
              expect(p.profiles[1].cmsSha256).toBe(p.profiles[0].cmsSha256);
            }
            const identity = {
              ownerId: principal,
              teamId: 'ABCDEFGHIJ',
              prefix: 'ABCDEFGHIJ',
              fingerprint: p.expected.fingerprint,
              expiresAt: Date.parse(cert.validTo),
              materialPath: 'materials/key.p12',
            };
            return {
              identity,
              profiles: Object.fromEntries(
                p.profiles.map((profile) => [
                  profile.bundleId,
                  {
                    ...identity,
                    bundleId: profile.bundleId,
                    cmsSha256: profile.cmsSha256,
                    certificateSha256: createHash('sha256').update(cert.raw).digest('hex'),
                    udids: ['a'.repeat(40)],
                    entitlements: {
                      'application-identifier': 'ABCDEFGHIJ.' + profile.bundleId,
                      'com.apple.developer.team-identifier': 'ABCDEFGHIJ',
                      'get-task-allow': false,
                    },
                    materialPath:
                      'materials/profile_' +
                      hash(profile.bundleId).slice(0, 32) +
                      '.mobileprovision',
                  },
                ]),
              ),
              udid: mode === 'wrong-device' ? 'b'.repeat(40) : 'a'.repeat(40),
              deviceOs: mode === 'wrong-os' ? '19.0' : p.expected.deviceOs,
            } as T;
          },
        },
      });
      const components = [
        {
          kind: 'app' as const,
          path: 'Payload/Fixture.app',
          bundleId: 'test.fixture',
          platform: 'ios',
          architectures: ['arm64'],
          encrypted: false,
          entitlements: {},
          minOs: '17.0',
        },
        {
          kind: 'appex' as const,
          path: 'Payload/Fixture.app/PlugIns/Widget.appex',
          bundleId: 'test.fixture.widget',
          platform: 'ios',
          architectures: ['arm64'],
          encrypted: false,
          entitlements: {},
          minOs: '17.0',
        },
      ];
      const input = {
        grant,
        analysis: {
          sha256: grant.uploadDigest,
          bundleId: 'test.fixture',
          version: '1',
          title: 'Fixture',
          components,
        },
        targets:
          mode === 'preserve'
            ? { 'test.fixture': 'test.fixture', 'test.fixture.widget': 'test.fixture.widget' }
            : { 'test.fixture': 'test.copy', 'test.fixture.widget': 'test.copy.widget' },
        signal: new AbortController().signal,
      };
      if (mode === 'shared-ready')
        await db.query(
          "UPDATE jobs SET connection_owner_id='o',access_grant_id=$1,access_grant_generation=1 WHERE id='j'",
          [shareId],
        );
      expect(await planner.canPreserve(grant, 'test.fixture')).toBe(mode === 'preserve');
      expect(apiCalls).toBe(0);
      await expect(planner.canPreserve(grant, 'invalid.*')).rejects.toThrow('INVALID_BUNDLE_ID');
      await expect(
        planner.canPreserve({ ...grant, leaseToken: 'stale' }, 'test.fixture'),
      ).rejects.toThrow('STALE_EXECUTOR_LEASE');
      if (mode === 'scope-error' || mode === 'scope-ambiguous') {
        await expect(planner.provision(input)).rejects.toThrow(
          mode === 'scope-error'
            ? 'synthetic permission failure'
            : 'RESOURCE_RECONCILIATION_AMBIGUOUS',
        );
        expect(posts).toBe(0);
      } else if (mode === 'profile-inactive') {
        await expect(planner.provision(input)).rejects.toThrow('PROFILE_NOT_READY');
        expect((await db.query('SELECT id FROM identities')).rows).toHaveLength(0);
      } else if (mode === 'uncertain-committed') {
        await expect(planner.provision(input)).rejects.toThrow('PROVISIONING_REJECTED');
        const first = posts;
        const result = await planner.provision(input);
        expect(Object.keys(result.profiles)).toEqual(['test.copy', 'test.copy.widget']);
        expect(posts).toBe(first);
        expect(profiles).toHaveLength(1);
      } else if (mode === 'uncertain') {
        await expect(planner.provision(input)).rejects.toThrow('PROVISIONING_REJECTED');
        const first = posts;
        await expect(planner.provision(input)).rejects.toThrow('RESOURCE_RECONCILIATION_REQUIRED');
        expect(posts).toBe(first);
      } else if (mode === 'wrong-device' || mode === 'wrong-os') {
        await expect(planner.provision(input)).rejects.toThrow('MATERIAL_BINDING_MISMATCH');
        expect((await db.query('SELECT id FROM identities')).rows).toHaveLength(0);
        expect(dataKey.equals(Buffer.alloc(32))).toBe(true);
      } else {
        const result = await planner.provision(input);
        expect(result.deviceOs).toBe(
          mode === 'unknown-os' ? null : mode === 'build-os' ? '23A345' : '18.0',
        );
        expect(Object.keys(result.profiles)).toEqual(Object.values(input.targets));
        expect((await db.query('SELECT id FROM identities')).rows).toHaveLength(1);
        expect((await db.query('SELECT id FROM profiles')).rows).toHaveLength(2);
        expect(dataKey.equals(Buffer.alloc(32))).toBe(true);
        expect(posts).toBe(mode === 'wildcard-existing' || mode === 'renewal' ? 1 : 2);
        expect(bundles.map((b) => b.attributes.identifier)).toEqual(
          mode === 'exact' ? ['test.copy', 'test.copy.widget'] : ['*'],
        );
        expect(profiles).toHaveLength(mode === 'exact' ? 2 : 1);
        if (mode === 'wildcard-existing') {
          await db.query(
            "UPDATE mappings SET original_id='another.fixture',target_id='another.fixture' WHERE id='mapping'",
          );
          const result = await planner.provision({
            ...input,
            analysis: {
              ...input.analysis,
              bundleId: 'another.fixture',
              components: components.map((c) => ({
                ...c,
                bundleId: c.bundleId.replace('test.fixture', 'another.fixture'),
              })),
            },
            targets: {
              'another.fixture': 'another.fixture',
              'another.fixture.widget': 'another.fixture.widget',
            },
          });
          expect(Object.keys(result.profiles)).toEqual([
            'another.fixture',
            'another.fixture.widget',
          ]);
          expect(profiles).toHaveLength(1);
          expect(posts).toBe(1);
        }
        if (mode === 'renewal') {
          const oldName = String(profiles[0].attributes.name);
          now += 1000;
          profiles[0].attributes.expirationDate = new Date(now - 1).toISOString();
          await planner.provision(input);
          expect(profiles).toHaveLength(2);
          expect(profiles[1].attributes.name).toBe(oldName + '-r1');
          expect(posts).toBe(2);
        }
      }
    } finally {
      await db.close();
    }
  });
