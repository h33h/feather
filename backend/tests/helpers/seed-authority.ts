import type { Database } from '../../packages/core/src/shared/database';
/** Seed explicit own bindings for trusted fixture rows, before invoking domain code. */
export async function ownAuthority(db: Database) {
  const connections = (
    await db.query<{ id: string; owner_id: string }>(
      "SELECT id,owner_id FROM connections WHERE provider='asc' AND state<>'disconnected' ORDER BY id",
    )
  ).rows;
  for (const c of connections)
    await db.query(
      'INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES($1,$2,$1) ON CONFLICT(user_id) DO NOTHING',
      [c.owner_id, c.id],
    );
  for (const table of ['jobs', 'devices', 'mappings', 'artifacts'])
    await db.query(
      'UPDATE ' +
        table +
        ' t SET connection_owner_id=t.owner_id WHERE t.connection_owner_id IS NULL AND EXISTS(SELECT 1 FROM connections c WHERE c.id=t.connection_id AND c.owner_id=t.owner_id)',
    );
}
