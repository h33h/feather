import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import {
  DatabaseBootstrapPort,
  BOOTSTRAP_SCHEMA,
} from '../packages/core/src/apple/bootstrap-store';
it('fences bootstrap leases and requires ciphertext before certificate claim', async () => {
  const db = await createDatabase();
  await db.query(BOOTSTRAP_SCHEMA);
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','a@b.c',0)");
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','pending:c','validating','asc')",
  );
  const port = new DatabaseBootstrapPort({
    db,
    now: () => 1,
    prepareIdentity: async () => ({
      secretRef: 'missing',
      csr: '-----BEGIN CERTIFICATE REQUEST-----\nfixture',
      spkiSha256: 'a'.repeat(64),
    }),
    findCertificates: async () => [],
    createCertificate: async () => {
      throw Error('must not POST');
    },
  });
  const lease = await port.acquire('o', 'c', 1);
  await expect(port.acquire('o', 'c', 1)).rejects.toThrow('BOOTSTRAP_BUSY');
  await expect(port.prepareIdentity(lease)).rejects.toThrow('BOOTSTRAP_KEY_NOT_PERSISTED');
  await db.query("UPDATE connections SET generation=2 WHERE id='c'");
  await expect(port.assertCurrent(lease)).rejects.toThrow('STALE_BOOTSTRAP_LEASE');
  await db.close();
});
it('persists one identity and refuses duplicate uncertain certificate POST', async () => {
  const db = await createDatabase();
  try {
    await db.query(BOOTSTRAP_SCHEMA);
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','c@b.c',0)");
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','pending:c','validating','asc')",
    );
    const identity = {
      secretRef: 'sealed',
      csr: '-----BEGIN CERTIFICATE REQUEST-----\nfixture',
      spkiSha256: 'a'.repeat(64),
    };
    await db.query(
      "INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag,generation) VALUES('sealed','o','c','distribution-key','wrapped','nonce','cipher','tag',1)",
    );
    let posts = 0,
      prepares = 0;
    let now = 1;
    const port = new DatabaseBootstrapPort({
      db,
      now: () => now,
      prepareIdentity: async () => {
        prepares++;
        return identity;
      },
      findCertificates: async () => [],
      createCertificate: async () => {
        posts++;
        throw Error('uncertain');
      },
    });
    const first = await port.acquire('o', 'c', 1);
    expect(await port.prepareIdentity(first)).toEqual(identity);
    expect(await port.prepareIdentity(first)).toEqual(identity);
    expect(await port.claimCertificate(first, identity)).toBe('new');
    await expect(port.createCertificate(first, identity.csr)).rejects.toThrow('uncertain');
    await expect(port.createCertificate(first, identity.csr)).rejects.toThrow(
      'CERTIFICATE_OPERATION_UNCLAIMED',
    );
    now = 1000000;
    const second = await port.acquire('o', 'c', 1);
    expect(await port.prepareIdentity(second)).toEqual(identity);
    expect(await port.claimCertificate(second, identity)).toBe('reconcile');
    expect(posts).toBe(1);
    expect(prepares).toBe(1);
  } finally {
    await db.close();
  }
});
