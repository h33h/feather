import { createHash } from 'node:crypto';
import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { NativeSessions } from '../packages/core/src/auth/native-sessions';
import { hash } from '../packages/core/src/shared/identifiers';
import { resetCredentials } from '../packages/core/src/auth/passkeys';
import { AdminUsers } from '../packages/core/src/auth/admin';
import { AccountLifecycle } from '../packages/core/src/auth/account-lifecycle';
const callback = 'isign-feather://auth/callback',
  verifier = 'v'.repeat(43),
  challenge = createHash('sha256').update(verifier).digest('base64url');
async function fixture() {
  const db = await createDatabase();
  let now = 1000000;
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('u','user',1),('other','other',1)",
  );
  await db.query(
    "INSERT INTO users(id,login_name,created_at,role) VALUES('admin','admin',1,'admin')",
  );
  const native = new NativeSessions(db, {
    origin: 'https://isign.example.test',
    callback,
    now: () => now,
  });
  const web = async (owner = 'u', verifiedAt = now) => {
    const raw = owner + verifiedAt;
    await db.query(
      'INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(token_hash) DO UPDATE SET verified_at=$4',
      [hash(raw), owner, hash('csrf'), verifiedAt, now + 86400000],
    );
    return raw;
  };
  const start = (sessionId?: string) =>
    native.start({
      state: 's'.repeat(43),
      codeChallenge: challenge,
      redirectUri: callback,
      ...(sessionId ? { sessionId } : {}),
    });
  const finish = async (transactionId: string, owner = 'u') =>
    new URL((await native.complete(transactionId, await web(owner))).callbackUrl).searchParams.get(
      'code',
    )!;
  const exchange = (transactionId: string, code: string, codeVerifier = verifier) =>
    native.exchange({ transactionId, code, codeVerifier, redirectUri: callback });
  const login = async () => {
    const s = await start();
    return exchange(s.transactionId, await finish(s.transactionId));
  };
  return {
    db,
    native,
    web,
    start,
    finish,
    exchange,
    login,
    setNow: (n: number) => {
      now = n;
    },
    getNow: () => now,
  };
}
it('requires S256, preserves state, hashes stored credentials and redeems a code once', async () => {
  const f = await fixture(),
    s = await f.start();
  expect(s.authorizationUrl).toBe(
    'https://isign.example.test/native/authorize?transactionId=' + s.transactionId,
  );
  const result = await f.native.complete(s.transactionId, await f.web()),
    url = new URL(result.callbackUrl),
    code = url.searchParams.get('code')!;
  expect(result.callbackUrl.startsWith(callback + '?')).toBe(true);
  expect(url.searchParams.get('state')).toBe('s'.repeat(43));
  await expect(f.exchange(s.transactionId, code, 'x'.repeat(43))).rejects.toThrow(
    'NATIVE_AUTH_INVALID',
  );
  const tokens = await f.exchange(s.transactionId, code);
  expect(await f.native.authorize(tokens.accessToken)).toMatchObject({
    ownerId: 'u',
    sessionId: tokens.sessionId,
    role: 'user',
    verifiedAt: 1000000,
    expiresAt: 1900000,
  });
  await expect(f.exchange(s.transactionId, code)).rejects.toThrow('NATIVE_AUTH_INVALID');
  const rows =
    JSON.stringify((await f.db.query('SELECT * FROM native_sessions')).rows) +
    JSON.stringify((await f.db.query('SELECT * FROM native_refresh_tokens')).rows) +
    JSON.stringify((await f.db.query('SELECT * FROM native_auth_transactions')).rows);
  for (const raw of [tokens.accessToken, tokens.refreshToken, code, s.transactionId])
    expect(rows).not.toContain(raw);
});
it('rejects malformed state, PKCE and callback before persisting a transaction', async () => {
  const f = await fixture();
  for (const input of [
    { state: '' },
    { state: 's'.repeat(513) },
    { codeChallenge: 'plain' },
    { redirectUri: callback + '/' },
    { redirectUri: 'isign-feather://evil/callback' },
  ])
    await expect(
      f.native.start({
        state: 's'.repeat(43),
        codeChallenge: challenge,
        redirectUri: callback,
        ...input,
      }),
    ).rejects.toThrow('NATIVE_AUTH_INVALID');
  expect((await f.db.query('SELECT * FROM native_auth_transactions')).rows).toHaveLength(0);
});
it('expires transaction at five minutes and code at sixty seconds exactly', async () => {
  const f = await fixture(),
    a = await f.start();
  f.setNow(1300000);
  await expect(f.finish(a.transactionId)).rejects.toThrow('NATIVE_AUTH_INVALID');
  const b = await f.start(),
    code = await f.finish(b.transactionId);
  f.setNow(1360000);
  await expect(f.exchange(b.transactionId, code)).rejects.toThrow('NATIVE_AUTH_INVALID');
});
it('expires freshness at ten minutes, access at fifteen, and refresh preserves verifiedAt', async () => {
  const f = await fixture(),
    tokens = await f.login();
  f.setNow(1599999);
  await f.native.requireFresh(tokens.accessToken);
  f.setNow(1600000);
  await expect(f.native.requireFresh(tokens.accessToken)).rejects.toThrow('FRESH_AUTH_REQUIRED');
  const rotated = await f.native.refresh(tokens.refreshToken);
  expect((await f.native.authorize(rotated.accessToken)).verifiedAt).toBe(1000000);
  f.setNow(rotated.expiresAt);
  await expect(f.native.authorize(rotated.accessToken)).rejects.toThrow('UNAUTHENTICATED');
});
it('atomically rotates refresh and revokes its family when an old token is replayed', async () => {
  const f = await fixture(),
    tokens = await f.login(),
    results = await Promise.allSettled([
      f.native.refresh(tokens.refreshToken),
      f.native.refresh(tokens.refreshToken),
    ]);
  expect(results.filter((x) => x.status === 'fulfilled')).toHaveLength(1);
  const rotated = (
    results.find((x) => x.status === 'fulfilled') as PromiseFulfilledResult<
      Awaited<ReturnType<typeof f.native.refresh>>
    >
  ).value;
  await expect(f.native.authorize(rotated.accessToken)).rejects.toThrow('UNAUTHENTICATED');
  await expect(f.native.refresh(rotated.refreshToken)).rejects.toThrow('UNAUTHENTICATED');
});
it('expires refresh at thirty days and logout invalidates both credentials', async () => {
  const f = await fixture(),
    first = await f.login();
  expect(first.refreshExpiresAt).toBe(1000000 + 30 * 86400000);
  f.setNow(first.refreshExpiresAt);
  await expect(f.native.refresh(first.refreshToken)).rejects.toThrow('UNAUTHENTICATED');
  const second = await f.login();
  await f.native.logout(second.accessToken);
  await expect(f.native.authorize(second.accessToken)).rejects.toThrow('UNAUTHENTICATED');
  await expect(f.native.refresh(second.refreshToken)).rejects.toThrow('UNAUTHENTICATED');
});
it('binds step-up to same owner and same session using renewed browser verification', async () => {
  const f = await fixture(),
    first = await f.login(),
    second = await f.login();
  f.setNow(1600000);
  const s = await f.start(first.sessionId);
  await expect(f.native.complete(s.transactionId, await f.web('other'))).rejects.toThrow(
    'NATIVE_AUTH_INVALID',
  );
  await expect(f.native.complete(s.transactionId, await f.web('u', 1000000))).rejects.toThrow(
    'NATIVE_AUTH_INVALID',
  );
  const fresh = await f.exchange(s.transactionId, await f.finish(s.transactionId));
  expect(fresh.sessionId).toBe(first.sessionId);
  expect((await f.native.requireFresh(fresh.accessToken)).verifiedAt).toBe(1600000);
  await expect(f.native.requireFresh(second.accessToken)).rejects.toThrow('FRESH_AUTH_REQUIRED');
  expect((await f.db.query('SELECT id FROM native_sessions')).rows).toHaveLength(2);
});
it('does not complete a step-up after logout', async () => {
  const f = await fixture(),
    tokens = await f.login(),
    s = await f.start(tokens.sessionId);
  await f.native.logout(tokens.accessToken);
  await expect(f.finish(s.transactionId)).rejects.toThrow('NATIVE_AUTH_INVALID');
});
it('reads role live and rejects blocked/deleted owners', async () => {
  const f = await fixture(),
    tokens = await f.login();
  await f.db.query("UPDATE users SET role='admin' WHERE id='u'");
  expect((await f.native.authorize(tokens.accessToken)).role).toBe('admin');
  for (const column of ['blocked_at', 'deleted_at']) {
    await f.db.query(`UPDATE users SET ${column}=1 WHERE id='u'`);
    await expect(f.native.authorize(tokens.accessToken)).rejects.toThrow('UNAUTHENTICATED');
    await expect(f.native.refresh(tokens.refreshToken)).rejects.toThrow('UNAUTHENTICATED');
    await f.db.query(`UPDATE users SET ${column}=NULL WHERE id='u'`);
  }
});
it.each(['reset', 'block', 'delete'])('invalidates sessions and handoffs on %s', async (action) => {
  const f = await fixture(),
    tokens = await f.login(),
    s = await f.start(tokens.sessionId);
  if (action === 'reset') await f.db.transaction((tx) => resetCredentials(tx, 'u', f.getNow()));
  if (action === 'block')
    await new AdminUsers(f.db, {} as never, f.getNow).setBlocked('admin', 'u', true);
  if (action === 'delete')
    await new AccountLifecycle(f.db, f.getNow, {} as never).removeProfile('u');
  if (action === 'block')
    await new AdminUsers(f.db, {} as never, f.getNow).setBlocked('admin', 'u', false);
  await expect(f.native.authorize(tokens.accessToken)).rejects.toThrow('UNAUTHENTICATED');
  await expect(f.native.refresh(tokens.refreshToken)).rejects.toThrow('UNAUTHENTICATED');
  await expect(f.finish(s.transactionId)).rejects.toThrow();
});
it('accepts code one millisecond before expiry and rejects a second completion', async () => {
  const f = await fixture(),
    s = await f.start(),
    code = await f.finish(s.transactionId);
  await expect(f.finish(s.transactionId)).rejects.toThrow('NATIVE_AUTH_INVALID');
  f.setNow(1059999);
  await f.exchange(s.transactionId, code);
});
it('redeems a code atomically and does not revive a logged-out completed step-up', async () => {
  const f = await fixture(),
    s = await f.start(),
    code = await f.finish(s.transactionId),
    results = await Promise.allSettled([
      f.exchange(s.transactionId, code),
      f.exchange(s.transactionId, code),
    ]);
  expect(results.filter((x) => x.status === 'fulfilled')).toHaveLength(1);
  const tokens = (
      results.find((x) => x.status === 'fulfilled') as PromiseFulfilledResult<
        Awaited<ReturnType<typeof f.exchange>>
      >
    ).value,
    step = await f.start(tokens.sessionId),
    stepCode = await f.finish(step.transactionId);
  await f.native.logout(tokens.accessToken);
  await expect(f.exchange(step.transactionId, stepCode)).rejects.toThrow('NATIVE_AUTH_INVALID');
});
it('cannot redeem a code for an alternate callback', async () => {
  const f = await fixture(),
    s = await f.start(),
    code = await f.finish(s.transactionId);
  await expect(
    f.native.exchange({
      transactionId: s.transactionId,
      code,
      codeVerifier: verifier,
      redirectUri: callback + '/',
    }),
  ).rejects.toThrow('NATIVE_AUTH_INVALID');
  await f.exchange(s.transactionId, code);
});
it('rejects server startup when the native migration has not been applied', async () => {
  const { assertInitializedDatabase } =
    await import('../packages/core/src/infrastructure/database-init');
  const f = await fixture();
  await assertInitializedDatabase(f.db, { native: true });
  await f.db.exec('DROP TABLE native_auth_transactions');
  await expect(assertInitializedDatabase(f.db, { native: true })).rejects.toThrow(
    'DATABASE_UNINITIALIZED',
  );
});
it('applies the additive migration to a previous web-only schema and preserves web auth', async () => {
  const { readFile } = await import('node:fs/promises');
  const { assertInitializedDatabase } =
    await import('../packages/core/src/infrastructure/database-init');
  const f = await fixture();
  await f.db.exec(
    'DROP TABLE native_auth_transactions; DROP TABLE native_refresh_tokens; DROP TABLE native_sessions',
  );
  await assertInitializedDatabase(f.db);
  await f.db.transaction((tx) => resetCredentials(tx, 'u', f.getNow()));
  await f.db.exec(
    await readFile(
      new URL('../packages/db/migrations/20261031-native-feather.sql', import.meta.url),
      'utf8',
    ),
  );
  await assertInitializedDatabase(f.db, { native: true });
  const tokens = await f.login();
  expect((await f.native.authorize(tokens.accessToken)).ownerId).toBe('u');
});
it('rechecks a web cookie revoked by recovery while waiting for the owner lock', async () => {
  const f = await fixture(),
    web = await f.web(),
    s = await f.start();
  const native = new NativeSessions(
    {
      query: f.db.query.bind(f.db),
      close: f.db.close.bind(f.db),
      transaction: (work) =>
        f.db.transaction((tx) =>
          work({
            query: async <T>(sql: string, params?: unknown[]) => {
              // Deterministic interleaving: recovery commits before this owner lock returns.
              if (
                sql ===
                'SELECT id FROM users WHERE id=$1 AND blocked_at IS NULL AND deleted_at IS NULL FOR UPDATE'
              )
                await tx.query('DELETE FROM sessions WHERE token_hash=$1', [hash(web)]);
              return tx.query<T>(sql, params);
            },
          }),
        ),
    },
    { origin: 'https://isign.example.test', callback, now: f.getNow },
  );
  await expect(native.complete(s.transactionId, web)).rejects.toThrow('UNAUTHENTICATED');
});
