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
export async function assertInitializedDatabase(
  db: QueryDatabase,
  options: { native?: boolean } = {},
): Promise<void> {
  const schema = (
    await db.query<{ ready: boolean }>(`SELECT
    (SELECT count(*)=3 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name IN('role','blocked_at','login_name'))
    AND (SELECT count(*)=2 FROM information_schema.columns WHERE table_schema='public' AND table_name='user_apple_bindings' AND column_name IN('connection_owner_id','grant_id'))
    AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='artifacts' AND column_name='ready_at') AS ready`)
  ).rows[0];
  if (options.native) {
    const native = (
      await db.query<{ ready: boolean }>(`SELECT
      (SELECT count(*)=11 FROM information_schema.columns WHERE table_schema='public' AND table_name='feather_signing_identities' AND column_name IN('id','owner_id','connection_id','generation','revision','state','secret_ref','spki_sha256','lease_token','lease_until','replacement_for'))
      AND (SELECT count(*)=8 FROM information_schema.columns WHERE table_schema='public' AND table_name='feather_profile_operations' AND column_name IN('id','owner_id','identity_id','binding','request','state','resources','result'))
      AND (SELECT count(*)=7 FROM information_schema.columns WHERE table_schema='public' AND table_name='native_sessions' AND column_name IN('id','owner_id','access_hash','verified_at','expires_at','refresh_expires_at','revoked_at'))
      AND (SELECT count(*)=4 FROM information_schema.columns WHERE table_schema='public' AND table_name='native_refresh_tokens' AND column_name IN('token_hash','session_id','expires_at','used_at'))
      AND (SELECT count(*)=12 FROM information_schema.columns WHERE table_schema='public' AND table_name='native_auth_transactions' AND column_name IN('id_hash','state','code_challenge','redirect_uri','owner_id','session_id','created_at','expires_at','code_hash','code_expires_at','verified_at','consumed_at')) AS ready`)
    ).rows[0];
    if (!native?.ready) throw new Failure('DATABASE_UNINITIALIZED', 503);
  }
  if (
    !schema?.ready ||
    !(await db.query("SELECT id FROM users WHERE role='admin' AND deleted_at IS NULL LIMIT 1")).rows
      .length
  )
    throw new Failure('DATABASE_UNINITIALIZED', 503);
}
