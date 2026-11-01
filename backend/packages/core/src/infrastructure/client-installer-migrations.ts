import type { Database } from '../shared/database';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Failure } from '../shared';
import { assertInitializedDatabase } from './database-init';
/** Operator-only additive migration. Startup never repairs or creates this relation. */
export async function migrateClientInstaller(db: Database): Promise<{ applied: string[] }> {
  const name = '20261101-client-installer.sql';
  const sql = await readFile(new URL('../../../db/migrations/' + name, import.meta.url), 'utf8');
  const digest = createHash('sha256').update(sql).digest('hex');
  return db.transaction(async (tx) => {
    await tx.query('SELECT pg_advisory_xact_lock(736493)');
    await assertInitializedDatabase(tx);
    await tx.query(
      'CREATE TABLE IF NOT EXISTS isign_schema_migrations(id text PRIMARY KEY,sha256 text NOT NULL,applied_at bigint NOT NULL)',
    );
    const old = (
      await tx.query<{ sha256: string }>('SELECT sha256 FROM isign_schema_migrations WHERE id=$1', [
        name,
      ])
    ).rows[0];
    if (old && old.sha256 !== digest) throw new Failure('MIGRATION_CHECKSUM_MISMATCH', 409);
    const present = (
      await tx.query(
        "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='client_installations' AND column_name IN('id','owner_id','request_key','job_id','device_id','release_sha256','version','receive_started_at','created_at')",
      )
    ).rows.length;
    if ((present && present !== 9) || (old && present !== 9))
      throw new Failure('DATABASE_MIGRATION_INCOMPLETE', 409);
    if (!present)
      for (const statement of sql
        .split(';')
        .map((s) => s.trim())
        .filter(Boolean))
        await tx.query(statement);
    if (!old)
      await tx.query('INSERT INTO isign_schema_migrations(id,sha256,applied_at) VALUES($1,$2,$3)', [
        name,
        digest,
        Date.now(),
      ]);
    return { applied: present ? [] : [name] };
  });
}
