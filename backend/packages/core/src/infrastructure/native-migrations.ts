import type { Database } from '../shared/database';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Failure } from '../shared';
import { assertInitializedDatabase } from './database-init';
type Migration = { name: string } & (
  { kind: 'tables'; tables: string[] } | { kind: 'columns'; table: string; columns: string[] }
);
const migrations: Migration[] = [
  {
    kind: 'tables',
    name: '20261031-native-feather.sql',
    tables: ['native_sessions', 'native_refresh_tokens', 'native_auth_transactions'],
  },
  {
    kind: 'tables',
    name: '20261101-feather-signing.sql',
    tables: ['feather_signing_identities', 'feather_profile_operations'],
  },
  {
    kind: 'columns',
    name: '20261101-feather-renewal.sql',
    table: 'feather_signing_identities',
    columns: ['replacement_for'],
  },
];
/** Operator-only additive upgrade. It never recreates the main schema or repairs partial data. */
export async function migrateFeather(db: Database): Promise<{ applied: string[] }> {
  const files = await Promise.all(
    migrations.map(async (migration) => {
      const sql = await readFile(
        new URL('../../../db/migrations/' + migration.name, import.meta.url),
        'utf8',
      );
      return { ...migration, sql, digest: createHash('sha256').update(sql).digest('hex') };
    }),
  );
  return db.transaction(async (tx) => {
    await tx.query('SELECT pg_advisory_xact_lock(736493)');
    await assertInitializedDatabase(tx);
    await tx.query(
      'CREATE TABLE IF NOT EXISTS isign_schema_migrations(id text PRIMARY KEY,sha256 text NOT NULL,applied_at bigint NOT NULL)',
    );
    const applied: string[] = [];
    for (const migration of files) {
      const old = (
        await tx.query<{ sha256: string }>(
          'SELECT sha256 FROM isign_schema_migrations WHERE id=$1',
          [migration.name],
        )
      ).rows[0];
      if (old && old.sha256 !== migration.digest)
        throw new Failure('MIGRATION_CHECKSUM_MISMATCH', 409);
      const present =
        migration.kind === 'tables'
          ? (
              await tx.query<{ table_name: string }>(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_name=ANY($1::text[])",
                [migration.tables],
              )
            ).rows.length
          : (
              await tx.query<{ column_name: string }>(
                "SELECT column_name FROM information_schema.columns WHERE table_schema='public' AND table_name=$1 AND column_name=ANY($2::text[])",
                [migration.table, migration.columns],
              )
            ).rows.length;
      const expected =
        migration.kind === 'tables' ? migration.tables.length : migration.columns.length;
      if ((present > 0 && present !== expected) || (old && present !== expected))
        throw new Failure('DATABASE_MIGRATION_INCOMPLETE', 409);
      if (!present) {
        // These versioned files contain only plain DDL, no procedural SQL or embedded semicolons.
        for (const statement of migration.sql
          .split(';')
          .map((s) => s.trim())
          .filter(Boolean))
          await tx.query(statement);
        applied.push(migration.name);
      }
      if (!old)
        await tx.query(
          'INSERT INTO isign_schema_migrations(id,sha256,applied_at) VALUES($1,$2,$3)',
          [migration.name, migration.digest, Date.now()],
        );
    }
    await assertInitializedDatabase(tx, { native: true });
    return { applied };
  });
}
