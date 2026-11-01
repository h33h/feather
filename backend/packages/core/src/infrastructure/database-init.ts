import { readFile } from 'node:fs/promises';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure } from '../shared/errors';

/** Operator/test bootstrap only. Starting the service never recreates its schema. */
export async function initializeDatabase(db: Database): Promise<void> {
  const schema = await readFile(new URL('../../../db/schema.sql', import.meta.url), 'utf8');
  await db.transaction(async (tx) => {
    await tx.query('SELECT pg_advisory_xact_lock(736491)');
    const occupied = await tx.query(
      "SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f') LIMIT 1",
    );
    if (occupied.rows.length) throw new Failure('DATABASE_NOT_EMPTY', 409);
    // The checked-in schema contains plain DDL, with no procedural bodies or data import.
    for (const statement of schema
      .split(';')
      .map((sql) => sql.trim())
      .filter(Boolean))
      await tx.query(statement);
  });
}

/** Check the current schema before reading private files or performing cleanup. */
export async function assertInitializedDatabase(db: QueryDatabase): Promise<void> {
  const schema = await readFile(new URL('../../../db/schema.sql', import.meta.url), 'utf8');
  const required = [...schema.matchAll(/^CREATE TABLE ([a-z_]+) \(\n([\s\S]*?)^\);/gm)].flatMap(
    ([, table, body]) =>
      [...body.matchAll(/^  ([a-z_]+) [a-z]/gm)].map(([, column]) => `${table}.${column}`),
  );
  const columns = await db.query<{ name: string }>(
    "SELECT table_name||'.'||column_name AS name FROM information_schema.columns WHERE table_schema='public'",
  );
  const present = new Set(columns.rows.map((row) => row.name));
  if (!required.length || required.some((column) => !present.has(column)))
    throw new Failure('DATABASE_UNINITIALIZED', 503);
  const views = [...schema.matchAll(/^CREATE VIEW ([a-z_]+) AS/gm)].map(([, name]) => name);
  const currentViews = await db.query<{ table_name: string }>(
    "SELECT table_name FROM information_schema.views WHERE table_schema='public'",
  );
  const presentViews = new Set(currentViews.rows.map((row) => row.table_name));
  if (
    views.some((view) => !presentViews.has(view)) ||
    !(await db.query("SELECT id FROM users WHERE role='admin' AND deleted_at IS NULL LIMIT 1")).rows
      .length
  )
    throw new Failure('DATABASE_UNINITIALIZED', 503);
}
