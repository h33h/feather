import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { loginFixture } from './helpers/login';
import { NativeSessions } from '../packages/core/src/auth/native-sessions';
import { hash, token } from '../packages/core/src/shared';
import type { Database, QueryDatabase } from '../packages/core/src/shared/database';
it('cleanup postpones family deletion while its handoff is live, avoiding cascade locks on an active exchange', async () => {
  const db = await createDatabase();
  let now = 1000000;
  const user = await loginFixture(db, 'cleanup-owner', now);
  await db.query(
    "INSERT INTO native_sessions(id,owner_id,access_hash,verified_at,expires_at,refresh_expires_at) VALUES('old',$1,$2,1,$3,$3)",
    [user.ownerId, hash(token()), now - 1],
  );
  const transaction = hash(token());
  await db.query(
    "INSERT INTO native_auth_transactions(id_hash,state,code_challenge,redirect_uri,owner_id,session_id,created_at,expires_at) VALUES($1,$2,$3,'isign-feather://auth/callback',$4,'old',$5,$6)",
    [transaction, token(), token(), user.ownerId, now - 10, now + 300000],
  );
  const auth = new NativeSessions(db, {
    origin: 'https://isign.example.test',
    callback: 'isign-feather://auth/callback',
    now: () => now,
  });
  const input = {
    state: token(),
    codeChallenge: token(),
    redirectUri: 'isign-feather://auth/callback',
  };
  await auth.start(input);
  expect(
    (await db.query('SELECT id_hash FROM native_auth_transactions WHERE id_hash=$1', [transaction]))
      .rows,
  ).toHaveLength(1);
  now += 300001;
  await auth.start(input);
  expect((await db.query("SELECT id FROM native_sessions WHERE id='old'")).rows).toHaveLength(0);
});
it('native admission never waits on the lifetime singleton lock held by production runtime', async () => {
  const db = await createDatabase();
  // PGlite serializes transactions; model only the external session-level lock it cannot hold independently.
  const guarded: Database = {
    query: db.query.bind(db),
    close: db.close.bind(db),
    transaction: async <T>(work: (tx: QueryDatabase) => Promise<T>) =>
      db.transaction((tx) =>
        work({
          query: async <R>(sql: string, params?: unknown[]) => {
            if (/pg_advisory_xact_lock\(736492\)/.test(sql))
              throw Error('LIFETIME_SINGLETON_LOCK_HELD');
            return tx.query<R>(sql, params);
          },
        }),
      ),
  };
  const auth = new NativeSessions(guarded, {
    origin: 'https://isign.example.test',
    callback: 'isign-feather://auth/callback',
    now: () => 1000,
  });
  await expect(
    auth.start({
      state: token(),
      codeChallenge: token(),
      redirectUri: 'isign-feather://auth/callback',
    }),
  ).resolves.toHaveProperty('transactionId');
});
