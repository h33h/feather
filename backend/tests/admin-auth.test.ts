import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { PersonalAuth } from '../packages/core/src/auth/passkeys';
async function fixture() {
  const db = await createDatabase();
  await db.query(
    "INSERT INTO users(id,login_name,role,created_at) VALUES('a','admin','admin',1),('u','user','user',1)",
  );
  const auth = new PersonalAuth(db, 'https://isign.example.test', () => 1000);
  const { AdminUsers } = await import('../packages/core/src/auth/admin');
  return { db, users: new AdminUsers(db, auth, () => 1000) };
}
it('checks the current database role for every admin action', async () => {
  const { db, users } = await fixture();
  await expect(users.invite('u', 'new')).rejects.toThrow('ADMIN_REQUIRED');
  await db.query("UPDATE users SET blocked_at=1 WHERE id='a'");
  await expect(users.list('a')).rejects.toThrow('ADMIN_REQUIRED');
});
it('invites beyond three users and returns no Apple or credential material in the list', async () => {
  const { users } = await fixture();
  for (const name of ['one', 'two', 'three', 'four']) await users.invite('a', name);
  const listed = await users.list('a');
  expect(listed).toHaveLength(6);
  for (const user of listed) {
    expect(user).not.toHaveProperty('public_key');
    expect(user).not.toHaveProperty('secret_ref');
  }
});
it('keeps the last active administrator and supports blocking ordinary accounts', async () => {
  const { db, users } = await fixture();
  await expect(users.setBlocked('a', 'a', true)).rejects.toThrow('LAST_ADMIN_REQUIRED');
  await users.setBlocked('a', 'u', true);
  expect((await db.query("SELECT blocked_at FROM users WHERE id='u'")).rows).toEqual([
    { blocked_at: 1000 },
  ]);
  await users.setBlocked('a', 'u', false);
  expect((await db.query("SELECT blocked_at FROM users WHERE id='u'")).rows).toEqual([
    { blocked_at: null },
  ]);
});
it('reinvites the same profile after invalidating old sessions and passkeys', async () => {
  const { db, users } = await fixture();
  await db.query(
    "INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES('old','u','csrf',1,999999)",
  );
  await db.query(
    "INSERT INTO passkeys(id,owner_id,public_key,counter,transports,created_at) VALUES('old','u','public',0,'[]',1)",
  );
  const invitation = await users.reinvite('a', 'u');
  expect(invitation.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect((await db.query("SELECT token_hash FROM sessions WHERE owner_id='u'")).rows).toHaveLength(
    0,
  );
  expect((await db.query("SELECT id FROM passkeys WHERE owner_id='u'")).rows).toHaveLength(0);
  expect((await db.query("SELECT id FROM users WHERE id='u'")).rows).toHaveLength(1);
});
