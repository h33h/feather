import { it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { BOOTSTRAP_SCHEMA } from '../packages/core/src/apple/bootstrap-store';
import { BootstrapRenewal } from '../packages/core/src/apple/bootstrap-renewal';
async function fixture() {
  const tmp = mkdtempSync(join(tmpdir(), 'isign-renewal-synthetic-'));
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
        join(tmp, 'key'),
        '-out',
        join(tmp, 'cert'),
        '-subj',
        '/CN=Synthetic certificate/OU=ABCDEFGHIJ',
        '-days',
        '1',
      ],
      { stdio: 'ignore' },
    );
    pem = readFileSync(join(tmp, 'cert'), 'utf8');
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
  const cert = new X509Certificate(pem);
  const db = await createDatabase();
  await db.query(BOOTSTRAP_SCHEMA);
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','o@test.example',1)");
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider,secret_ref,issuer_id,key_id) VALUES('c','o','ABCDEFGHIJ','ready','asc','p8','issuer','KEYID')",
  );
  await db.query(
    "INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag,generation) VALUES('p8','o','c','p8','w','n','cipher-p8','t',1),('key','o','c','distribution-key','w','n','cipher-key','t',1)",
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,name,status,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES('d','o','c','phone','ready',1,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
  );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','a','u',1,'digest','ready',1,9999999999999)",
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,device_id,state,idempotency_key,created_at,updated_at) VALUES('j','o','u','d','ready','key',1,1)",
  );
  await db.query(
    "INSERT INTO artifacts(id,owner_id,job_id,connection_id,device_id,object_key,digest,metadata,valid_until,created_at,expires_at,verified) VALUES('a','o','j','c','d','signed','signed','{\"generation\":1}',9999999999999,1,9999999999999,true)",
  );
  await db.query(
    "INSERT INTO tickets(token_hash,owner_id,artifact_id,state,expires_at) VALUES('ticket','o','a','ready',9999999999999)",
  );
  await db.query(
    "INSERT INTO bootstrap_operations(owner_id,connection_id,generation,nonce,expires_at,identity,certificate_state,certificate) VALUES('o','c',1,'old',100,$1,'committed',$2)",
    [
      JSON.stringify({
        secretRef: 'key',
        spkiSha256: createHash('sha256')
          .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
          .digest('hex'),
      }),
      JSON.stringify({ pem }),
    ],
  );
  return { db, cert };
}
it('expires owned material and capabilities while preserving P8 and generation', async () => {
  const f = await fixture();
  try {
    const now = Date.parse(f.cert.validTo) + 1;
    expect(await new BootstrapRenewal(f.db, () => now).prepare('o', 'c')).toMatchObject({
      generation: 1,
      state: 'action_required',
      reason: 'CERTIFICATE_REQUIRED',
    });
    expect(
      (
        await f.db.query<{ generation: number; secret_ref: string; last_error: string }>(
          'SELECT generation,secret_ref,last_error FROM connections',
        )
      ).rows[0],
    ).toEqual({ generation: 1, secret_ref: 'p8', last_error: 'CERTIFICATE_REQUIRED' });
    expect(
      (
        await f.db.query<{ deleted_at: number | null }>(
          "SELECT deleted_at FROM secrets WHERE id='p8'",
        )
      ).rows[0].deleted_at,
    ).toBeNull();
    expect((await f.db.query('SELECT * FROM secret_deletions')).rows).toHaveLength(1);
    expect(
      (
        await f.db.query<{
          identity: unknown;
          certificate: unknown;
          certificate_state: string;
          expires_at: number;
        }>('SELECT identity,certificate,certificate_state,expires_at FROM bootstrap_operations')
      ).rows[0],
    ).toEqual({ identity: null, certificate: null, certificate_state: 'prepared', expires_at: 0 });
    expect(
      (await f.db.query<{ status: string }>('SELECT status FROM devices')).rows[0].status,
    ).toBe('apple_processing');
    expect((await f.db.query<{ state: string }>('SELECT state FROM tickets')).rows[0].state).toBe(
      'revoked',
    );
    expect(
      (await f.db.query<{ valid_until: number }>('SELECT valid_until FROM artifacts')).rows[0]
        .valid_until,
    ).toBe(now);
  } finally {
    await f.db.close();
  }
});
it('requires expiry, ownership and no running job before mutations', async () => {
  const f = await fixture();
  try {
    const renewal = new BootstrapRenewal(f.db, () => Date.parse(f.cert.validTo) + 1);
    await expect(renewal.prepare('foreign', 'c')).rejects.toThrow('USER_UNAVAILABLE');
    await expect(
      new BootstrapRenewal(f.db, () => Date.parse(f.cert.validFrom) + 1).prepare('o', 'c'),
    ).rejects.toThrow('CERTIFICATE_NOT_EXPIRED');
    await f.db.query("UPDATE jobs SET state='signing'");
    await expect(renewal.prepare('o', 'c')).rejects.toThrow('ACTIVE_JOB_EXISTS');
    expect(
      (
        await f.db.query<{ deleted_at: number | null }>(
          "SELECT deleted_at FROM secrets WHERE id='key'",
        )
      ).rows[0].deleted_at,
    ).toBeNull();
  } finally {
    await f.db.close();
  }
});
