import { afterEach, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { BootstrapConnection } from '../packages/core/src/application/bootstrap-connection';
import { SigningReadiness } from '../packages/core/src/application/signing-readiness';
import { RuntimeReadiness } from '../packages/core/src/application/runtime-readiness';
import {
  AppleClientCredentials,
  type AppleClientFactory,
} from '../packages/core/src/application/apple-client-credentials';
import { createDatabase } from './helpers/database';
import { connectionFixture, deviceFixture, loginFixture } from './helpers/login';
import type { Database } from '../packages/core/src/shared/database';
import type { BootstrapRenewal } from '../packages/core/src/apple/bootstrap-renewal';
const databases: Database[] = [];
afterEach(async () => {
  await Promise.all(databases.splice(0).map((db) => db.close()));
});
async function fixture() {
  const db = await createDatabase();
  databases.push(db);
  const owner = (await loginFixture(db, 'bootstrap-application', 1000)).ownerId;
  const connection = await connectionFixture(db, owner, 'ABCDEFGHIJ');
  await db.query("UPDATE connections SET issuer_id='issuer',key_id='KEYID',secret_ref='p8'");
  const prove = vi.fn(async () => ({ teamId: 'ABCDEFGHIJ' }));
  const commit = vi.fn(async () => true);
  const prepare = vi.fn(async () => {
    await db.query(
      "UPDATE connections SET state='action_required',last_error='CERTIFICATE_REQUIRED'",
    );
  });
  const useCase = new BootstrapConnection(
    db,
    { prepare } as unknown as Pick<BootstrapRenewal, 'prepare'>,
    { prove },
    { commit },
    () => 1000,
  );
  return { db, owner, connection, prove, commit, prepare, useCase };
}
it('bootstraps missing material with the current generation and commits credentials', async () => {
  const f = await fixture();
  await expect(f.useCase.run(f.owner)).resolves.toEqual({ state: 'ready', teamId: 'ABCDEFGHIJ' });
  expect(f.prove).toHaveBeenCalledWith(f.owner, f.connection.id, 1);
  expect(f.commit).toHaveBeenCalledWith(f.owner, f.connection.id, 1, {
    issuerId: 'issuer',
    keyId: 'KEYID',
    secretRef: 'p8',
    teamId: 'ABCDEFGHIJ',
  });
  expect(f.prepare).not.toHaveBeenCalled();
});
it('rejects active queued work before changing a ready connection', async () => {
  const f = await fixture();
  const device = await deviceFixture(f.db, f.owner, f.connection.id, 'Phone', '18.0');
  await f.db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('upload',$1,'App.ipa','object',1,'digest','ready',1,999999)",
    [f.owner],
  );
  await f.db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,device_id,state,idempotency_key,created_at,updated_at) VALUES('job',$1,'upload',$2,'queued','key',1,1)",
    [f.owner, device.id],
  );
  await expect(f.useCase.run(f.owner)).rejects.toThrow('ACTIVE_JOB_EXISTS');
  expect((await f.db.query('SELECT state FROM connections')).rows).toEqual([{ state: 'ready' }]);
  expect(f.prove).not.toHaveBeenCalled();
});
it('prepares expired certificate material before proving and detects a lost generation at commit', async () => {
  const f = await fixture();
  await f.db.query(
    "INSERT INTO bootstrap_operations(owner_id,connection_id,generation,nonce,expires_at,certificate_state,certificate) VALUES($1,$2,1,'old',9999,'committed',$3)",
    [f.owner, f.connection.id, JSON.stringify({ expiresAt: 999 })],
  );
  f.commit.mockResolvedValueOnce(false);
  await expect(f.useCase.run(f.owner)).rejects.toThrow('CONNECTION_CHANGED');
  expect(f.prepare).toHaveBeenCalledWith(f.owner, f.connection.id);
  expect(f.prepare.mock.invocationCallOrder[0]).toBeLessThan(f.prove.mock.invocationCallOrder[0]);
});
it('rejects unavailable owners before contacting bootstrap', async () => {
  const f = await fixture();
  await expect(f.useCase.run('foreign')).rejects.toThrow('CONNECTION_UNAVAILABLE');
  expect(f.prove).not.toHaveBeenCalled();
});
it('refreshes missing signing material before reconciling the requesting owner', async () => {
  const f = await fixture();
  const bootstrap = vi.fn(async () => {}),
    reconcileOwner = vi.fn(async () => {});
  await new SigningReadiness(f.db, bootstrap, { reconcileOwner }, () => 1000).ensure(f.owner);
  expect(bootstrap).toHaveBeenCalledWith(f.owner);
  expect(reconcileOwner).toHaveBeenCalledWith(f.owner);
  expect(bootstrap.mock.invocationCallOrder[0]).toBeLessThan(
    reconcileOwner.mock.invocationCallOrder[0],
  );
  await expect(
    new SigningReadiness(f.db, undefined, { reconcileOwner }, () => 1000).ensure(f.owner),
  ).rejects.toThrow('BOOTSTRAP_BROKER_UNAVAILABLE');
});
it('checks database and KMS before requiring a complete native pipeline', async () => {
  const f = await fixture();
  const assertReady = vi.fn(async () => {}),
    broker = vi.fn(async () => {});
  await expect(
    new RuntimeReadiness(f.db, { assertReady }, undefined, broker, true).check(),
  ).rejects.toThrow('NATIVE_PIPELINE_UNAVAILABLE');
  expect(assertReady).toHaveBeenCalledOnce();
  expect(broker).not.toHaveBeenCalled();
  await new RuntimeReadiness(f.db, { assertReady }, true, broker, true).check();
  expect(broker).toHaveBeenCalledOnce();
});
it('binds bootstrap credentials to nonce, expiry and generation on every request and clears plaintext', async () => {
  const f = await fixture();
  const lease = {
    ownerId: f.owner,
    connectionId: f.connection.id,
    generation: 1,
    nonce: 'nonce',
    expiresAt: 10000,
  };
  await f.db.query("UPDATE connections SET state='validating'");
  await f.db.query(
    'INSERT INTO bootstrap_operations(owner_id,connection_id,generation,nonce,expires_at) VALUES($1,$2,1,$3,$4)',
    [f.owner, f.connection.id, lease.nonce, lease.expiresAt],
  );
  const plaintext = Buffer.from(
    generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }),
  );
  const openForBootstrap = vi.fn(async () => plaintext);
  const vault = { openForBootstrap, openForJob: vi.fn(), openForConnection: vi.fn() };
  const factory: AppleClientFactory = (_key, guard) => ({
    request: async () => {
      await guard();
      return { data: [] };
    },
  });
  const credentials = new AppleClientCredentials(f.db, vault, factory, () => 1000);
  const api = await credentials.bootstrap(lease);
  expect(plaintext.every((byte) => byte === 0)).toBe(true);
  await expect(api.findCertificates('a'.repeat(64))).resolves.toEqual([]);
  await f.db.query('UPDATE connections SET generation=2');
  await expect(api.findCertificates('a'.repeat(64))).rejects.toThrow('STALE_BOOTSTRAP_LEASE');
  await expect(credentials.bootstrap(lease)).rejects.toThrow('STALE_BOOTSTRAP_LEASE');
  expect(openForBootstrap).toHaveBeenCalledOnce();
});
it('rejects expired bootstrap leases before opening a credential', async () => {
  const f = await fixture();
  await f.db.query("UPDATE connections SET state='validating'");
  await f.db.query(
    "INSERT INTO bootstrap_operations(owner_id,connection_id,generation,nonce,expires_at) VALUES($1,$2,1,'old',999)",
    [f.owner, f.connection.id],
  );
  const vault = { openForBootstrap: vi.fn(), openForJob: vi.fn(), openForConnection: vi.fn() };
  const credentials = new AppleClientCredentials(f.db, vault, vi.fn(), () => 1000);
  await expect(
    credentials.bootstrap({
      ownerId: f.owner,
      connectionId: f.connection.id,
      generation: 1,
      nonce: 'old',
      expiresAt: 999,
    }),
  ).rejects.toThrow('STALE_BOOTSTRAP_LEASE');
  expect(vault.openForBootstrap).not.toHaveBeenCalled();
});
it('rechecks ready connection authority after opening credentials and clears plaintext', async () => {
  const f = await fixture();
  const plaintext = Buffer.from(
    generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }),
  );
  const vault = {
    openForBootstrap: vi.fn(),
    openForJob: vi.fn(),
    openForConnection: vi.fn(async () => plaintext),
  };
  const factory: AppleClientFactory = (_key, guard) => ({
    request: async () => {
      await guard();
      return { data: [] };
    },
  });
  const credentials = new AppleClientCredentials(f.db, vault, factory, () => 1000);
  const api = await credentials.ready({
    ownerId: f.owner,
    connectionId: f.connection.id,
    generation: 1,
  });
  expect(plaintext.every((byte) => byte === 0)).toBe(true);
  await expect(api.findCertificates('a'.repeat(64))).resolves.toEqual([]);
  await f.db.query('UPDATE connections SET generation=2');
  await expect(api.findCertificates('a'.repeat(64))).rejects.toThrow('APPLE_ACCESS_UNAVAILABLE');
});
it('rechecks onboarding validation generation before the first Apple request', async () => {
  const f = await fixture();
  await f.db.query("UPDATE connections SET state='validating',generation=2");
  const vault = { openForBootstrap: vi.fn(), openForJob: vi.fn(), openForConnection: vi.fn() };
  const factory: AppleClientFactory = (_key, guard) => ({
    request: async () => {
      await guard();
      return { data: [] };
    },
  });
  const credentials = new AppleClientCredentials(f.db, vault, factory, () => 1000);
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  await expect(
    credentials.validateTeam(
      { issuerId: 'issuer', keyId: 'KEYID', key },
      { ownerId: f.owner, connectionId: f.connection.id, generation: 1 },
    ),
  ).rejects.toThrow('CONNECTION_CHANGED');
});
