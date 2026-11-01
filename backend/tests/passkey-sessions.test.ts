import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { SessionService } from '../packages/core/src/auth/sessions';
import { hash } from '../packages/core/src/shared/identifiers';
it('requires fresh passkey verification and rejects a blocked session owner', async () => {
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('u','user',1)");
  await db.query(
    "INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,'u',$2,1,9999999)",
    [hash('raw'), hash('csrf')],
  );
  const sessions = new SessionService(db, { now: () => 600001 } as ConstructorParameters<
    typeof SessionService
  >[1]);
  await expect(
    sessions.fresh('raw', 'csrf', 'https://isign.example.test', 'https://isign.example.test'),
  ).rejects.toThrow('FRESH_AUTH_REQUIRED');
  await db.query("UPDATE users SET blocked_at=1 WHERE id='u'");
  await expect(sessions.session('raw')).rejects.toThrow('UNAUTHENTICATED');
});
it('reads the current role from the database rather than a previously cached login', async () => {
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('u','user',1)");
  await db.query(
    "INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,'u',$2,1,9999999)",
    [hash('raw'), hash('csrf')],
  );
  const sessions = new SessionService(db, { now: () => 1000 } as ConstructorParameters<
    typeof SessionService
  >[1]);
  expect(await sessions.session('raw')).toMatchObject({
    ownerId: 'u',
    role: 'user',
    loginName: 'user',
  });
  await db.query("UPDATE users SET role='admin' WHERE id='u'");
  expect(await sessions.session('raw')).toMatchObject({ role: 'admin' });
});
