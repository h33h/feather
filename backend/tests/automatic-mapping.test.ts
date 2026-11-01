import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { MappingService } from '../packages/core/src/signing/mapping';
it('keeps a stable automatically approved copy and maps extension suffixes consistently', async () => {
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1)");
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
  );
  const mapping = new MappingService(db);
  const first = await mapping.choose('o', 'c', 'com.example.app', false);
  expect(first.target_id).not.toBe('com.example.app');
  expect(await mapping.choose('o', 'c', 'com.example.app', true)).toEqual(first);
  expect(await mapping.extension('o', first.id, 'share')).toBe(first.target_id + '.share');
  await db.query("UPDATE connections SET generation=2,team_id='OTHER123' WHERE id='c'");
  const replacement = await mapping.choose('o', 'c', 'com.example.app', false);
  expect(replacement.target_id).not.toBe(first.target_id);
  await db.close();
});
