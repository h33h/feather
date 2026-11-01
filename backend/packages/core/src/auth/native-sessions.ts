import { createHash } from 'node:crypto';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure, hash, id, token } from '../shared/index';
import { SessionService } from './sessions';
export type NativePrincipal = {
  ownerId: string;
  role: 'user' | 'admin';
  loginName: string;
  publicProfileId: string;
  sessionId: string;
  verifiedAt: number;
  expiresAt: number;
};
export type NativeTokens = {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  sessionId: string;
  expiresAt: number;
  refreshExpiresAt: number;
};
type Transaction = {
  id_hash: string;
  state: string;
  code_challenge: string;
  redirect_uri: string;
  owner_id: string | null;
  session_id: string | null;
  created_at: number;
  expires_at: number;
  code_hash: string | null;
  code_expires_at: number | null;
  verified_at: number | null;
  consumed_at: number | null;
};
const invalid = () => new Failure('NATIVE_AUTH_INVALID', 400);
const unauthenticated = () => new Failure('UNAUTHENTICATED', 401);
const opaque = (value: string) => /^[A-Za-z0-9_-]{43}$/.test(value);
/** One fixed callback, S256 only. Raw credentials are returned once and never persisted. */
export class NativeSessions {
  private clock: () => number;
  constructor(
    private db: Database,
    private options: { origin: string; callback: string; now?: () => number },
  ) {
    if (options.callback !== 'isign-feather://auth/callback') throw invalid();
    this.clock = options.now ?? Date.now;
  }
  async start(input: {
    state: string;
    codeChallenge: string;
    redirectUri: string;
    sessionId?: string;
  }) {
    if (
      !/^[A-Za-z0-9_-]{16,512}$/.test(input.state) ||
      !opaque(input.codeChallenge) ||
      input.redirectUri !== this.options.callback
    )
      throw invalid();
    const raw = token(),
      now = this.clock(),
      expiresAt = now + 300000;
    // Independent, nonblocking cleanup statements never hold a handoff lock while
    // waiting for a family row that account recovery already locked.
    await this.db.query(
      'DELETE FROM native_auth_transactions WHERE id_hash IN (SELECT id_hash FROM native_auth_transactions WHERE expires_at<=$1 LIMIT 100 FOR UPDATE SKIP LOCKED)',
      [now],
    );
    await this.db.query(
      'DELETE FROM native_sessions WHERE id IN (SELECT s.id FROM native_sessions s WHERE s.refresh_expires_at<=$1 AND NOT EXISTS(SELECT 1 FROM native_auth_transactions t WHERE t.session_id=s.id) LIMIT 100 FOR UPDATE SKIP LOCKED)',
      [now],
    );
    await this.db.transaction(async (tx) => {
      // Serialize admission without scanning unbounded results.
      // 736492 is the production runtime's lifetime singleton lease, not an admission mutex.
      await tx.query('SELECT pg_advisory_xact_lock(736494)');
      if (
        (
          await tx.query(
            'SELECT id_hash FROM native_auth_transactions WHERE expires_at>$1 LIMIT 1001',
            [now],
          )
        ).rows.length >= 1000
      )
        throw new Failure('AUTH_RATE_LIMITED', 429);
      let owner: string | null = null;
      if (input.sessionId) {
        const ownerId = (
          await tx.query<{ owner_id: string }>('SELECT owner_id FROM native_sessions WHERE id=$1', [
            input.sessionId,
          ])
        ).rows[0]?.owner_id;
        if (!ownerId) throw unauthenticated();
        await this.availableOwner(tx, ownerId);
        const session = (
          await tx.query<{ owner_id: string }>(
            `SELECT s.owner_id FROM native_sessions s JOIN users u ON u.id=s.owner_id WHERE s.id=$1 AND s.revoked_at IS NULL AND s.expires_at>$2 AND s.refresh_expires_at>$2 AND u.blocked_at IS NULL AND u.deleted_at IS NULL FOR UPDATE OF s`,
            [input.sessionId, now],
          )
        ).rows[0];
        if (!session) throw unauthenticated();
        owner = session.owner_id;
      }
      await tx.query(
        'INSERT INTO native_auth_transactions(id_hash,state,code_challenge,redirect_uri,owner_id,session_id,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
        [
          hash(raw),
          input.state,
          input.codeChallenge,
          input.redirectUri,
          owner,
          input.sessionId ?? null,
          now,
          expiresAt,
        ],
      );
    });
    return {
      transactionId: raw,
      authorizationUrl: this.options.origin + '/native/authorize?transactionId=' + raw,
      expiresAt,
    };
  }
  async complete(transactionId: string, webSessionToken: string) {
    if (!opaque(transactionId)) throw invalid();
    return this.db.transaction(async (tx) => {
      const now = this.clock();
      const sessions = new SessionService(tx, { now: this.clock });
      const candidate = await sessions.session(webSessionToken);
      // Recheck the cookie after the owner lock: recovery may have revoked it while waiting.
      await this.availableOwner(tx, candidate.ownerId);
      const web = await sessions.session(webSessionToken);
      const row = await this.transaction(tx, transactionId, now);
      if (row.code_hash) throw invalid();
      if (
        web.verifiedAt < Number(row.created_at) ||
        web.verifiedAt > now ||
        now - web.verifiedAt >= 600000 ||
        (row.owner_id && row.owner_id !== web.ownerId)
      )
        throw invalid();
      if (row.session_id) await this.boundSession(tx, row, now);
      const code = token();
      await tx.query(
        'UPDATE native_auth_transactions SET owner_id=$2,code_hash=$3,code_expires_at=$4,verified_at=$5 WHERE id_hash=$1',
        [
          row.id_hash,
          web.ownerId,
          hash(code),
          Math.min(now + 60000, Number(row.expires_at)),
          web.verifiedAt,
        ],
      );
      const callback = new URL(this.options.callback);
      callback.searchParams.set('transactionId', transactionId);
      callback.searchParams.set('state', row.state);
      callback.searchParams.set('code', code);
      return { callbackUrl: callback.toString() };
    });
  }
  async exchange(input: {
    transactionId: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
  }): Promise<NativeTokens> {
    if (
      !opaque(input.transactionId) ||
      !opaque(input.code) ||
      !/^[A-Za-z0-9._~-]{43,128}$/.test(input.codeVerifier) ||
      input.redirectUri !== this.options.callback
    )
      throw invalid();
    return this.db.transaction(async (tx) => {
      const now = this.clock();
      const owner = (
        await tx.query<{ owner_id: string | null }>(
          'SELECT owner_id FROM native_auth_transactions WHERE id_hash=$1',
          [hash(input.transactionId)],
        )
      ).rows[0]?.owner_id;
      if (!owner) throw invalid();
      await this.availableOwner(tx, owner);
      const row = await this.transaction(tx, input.transactionId, now);
      if (
        !row.owner_id ||
        row.code_hash !== hash(input.code) ||
        Number(row.code_expires_at) <= now ||
        row.redirect_uri !== input.redirectUri ||
        createHash('sha256').update(input.codeVerifier).digest('base64url') !== row.code_challenge
      )
        throw invalid();
      let sessionId: string = id(),
        refreshExpiresAt = now + 30 * 86400000;
      if (row.session_id) {
        const session = await this.boundSession(tx, row, now);
        sessionId = row.session_id;
        refreshExpiresAt = Number(session.refresh_expires_at);
        await tx.query(
          'UPDATE native_refresh_tokens SET used_at=$2 WHERE session_id=$1 AND used_at IS NULL',
          [sessionId, now],
        );
      }
      await tx.query('UPDATE native_auth_transactions SET consumed_at=$2 WHERE id_hash=$1', [
        row.id_hash,
        now,
      ]);
      return this.issue(
        tx,
        { sessionId, ownerId: row.owner_id, verifiedAt: Number(row.verified_at), refreshExpiresAt },
        now,
        !row.session_id,
      );
    });
  }
  private async transaction(tx: QueryDatabase, raw: string, now: number) {
    const row = (
      await tx.query<Transaction>(
        'SELECT * FROM native_auth_transactions WHERE id_hash=$1 AND expires_at>$2 AND consumed_at IS NULL FOR UPDATE',
        [hash(raw), now],
      )
    ).rows[0];
    if (!row) throw invalid();
    return row;
  }
  private async availableOwner(tx: QueryDatabase, owner: string) {
    if (
      !(
        await tx.query(
          'SELECT id FROM users WHERE id=$1 AND blocked_at IS NULL AND deleted_at IS NULL FOR UPDATE',
          [owner],
        )
      ).rows.length
    )
      throw unauthenticated();
  }
  private async boundSession(tx: QueryDatabase, row: Transaction, now: number) {
    const session = (
      await tx.query<{ refresh_expires_at: number }>(
        'SELECT refresh_expires_at FROM native_sessions WHERE id=$1 AND owner_id=$2 AND revoked_at IS NULL AND refresh_expires_at>$3 FOR UPDATE',
        [row.session_id, row.owner_id, now],
      )
    ).rows[0];
    if (!session) throw invalid();
    return session;
  }
  private async issue(
    tx: QueryDatabase,
    session: { sessionId: string; ownerId: string; verifiedAt: number; refreshExpiresAt: number },
    now: number,
    create = false,
  ): Promise<NativeTokens> {
    const accessToken = token(),
      refreshToken = token(),
      expiresAt = Math.min(now + 900000, session.refreshExpiresAt);
    if (create)
      await tx.query(
        'INSERT INTO native_sessions(id,owner_id,access_hash,verified_at,expires_at,refresh_expires_at) VALUES($1,$2,$3,$4,$5,$6)',
        [
          session.sessionId,
          session.ownerId,
          hash(accessToken),
          session.verifiedAt,
          expiresAt,
          session.refreshExpiresAt,
        ],
      );
    else
      await tx.query(
        'UPDATE native_sessions SET access_hash=$2,verified_at=$3,expires_at=$4 WHERE id=$1',
        [session.sessionId, hash(accessToken), session.verifiedAt, expiresAt],
      );
    await tx.query(
      'INSERT INTO native_refresh_tokens(token_hash,session_id,expires_at) VALUES($1,$2,$3)',
      [hash(refreshToken), session.sessionId, session.refreshExpiresAt],
    );
    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      sessionId: session.sessionId,
      expiresAt,
      refreshExpiresAt: session.refreshExpiresAt,
    };
  }
  async refresh(refreshToken: string): Promise<NativeTokens> {
    if (!opaque(refreshToken)) throw unauthenticated();
    // Replay revocation must commit before returning the authentication error.
    const result = await this.db.transaction(async (tx) => {
      const now = this.clock();
      const owner = (
        await tx.query<{ owner_id: string }>(
          'SELECT s.owner_id FROM native_refresh_tokens r JOIN native_sessions s ON s.id=r.session_id WHERE r.token_hash=$1',
          [hash(refreshToken)],
        )
      ).rows[0]?.owner_id;
      if (!owner) return null;
      await this.availableOwner(tx, owner);
      const row = (
        await tx.query<{
          id: string;
          owner_id: string;
          verified_at: number;
          refresh_expires_at: number;
          revoked_at: number | null;
          used_at: number | null;
          expires_at: number;
        }>(
          `SELECT s.id,s.owner_id,s.verified_at,s.refresh_expires_at,s.revoked_at,r.used_at,r.expires_at FROM native_refresh_tokens r JOIN native_sessions s ON s.id=r.session_id WHERE r.token_hash=$1 FOR UPDATE OF s,r`,
          [hash(refreshToken)],
        )
      ).rows[0];
      if (
        !row ||
        row.revoked_at !== null ||
        Number(row.refresh_expires_at) <= now ||
        Number(row.expires_at) <= now
      )
        return null;
      if (row.used_at !== null) {
        await tx.query('UPDATE native_sessions SET revoked_at=$2 WHERE id=$1', [row.id, now]);
        return null;
      }
      await tx.query('UPDATE native_refresh_tokens SET used_at=$2 WHERE token_hash=$1', [
        hash(refreshToken),
        now,
      ]);
      return this.issue(
        tx,
        {
          sessionId: row.id,
          ownerId: row.owner_id,
          verifiedAt: Number(row.verified_at),
          refreshExpiresAt: Number(row.refresh_expires_at),
        },
        now,
      );
    });
    if (!result) throw unauthenticated();
    return result;
  }
  async authorize(accessToken: string): Promise<NativePrincipal> {
    if (!opaque(accessToken)) throw unauthenticated();
    const row = (
      await this.db.query<{
        owner_id: string;
        role: 'user' | 'admin';
        login_name: string;
        public_profile_id: string;
        id: string;
        verified_at: number;
        expires_at: number;
      }>(
        `SELECT s.owner_id,u.role,u.login_name,u.public_profile_id,s.id,s.verified_at,s.expires_at FROM native_sessions s JOIN users u ON u.id=s.owner_id WHERE s.access_hash=$1 AND s.expires_at>$2 AND s.refresh_expires_at>$2 AND s.revoked_at IS NULL AND u.blocked_at IS NULL AND u.deleted_at IS NULL`,
        [hash(accessToken), this.clock()],
      )
    ).rows[0];
    if (!row) throw unauthenticated();
    return {
      ownerId: row.owner_id,
      role: row.role,
      loginName: row.login_name,
      publicProfileId: row.public_profile_id,
      sessionId: row.id,
      verifiedAt: Number(row.verified_at),
      expiresAt: Number(row.expires_at),
    };
  }
  async requireFresh(accessToken: string) {
    const principal = await this.authorize(accessToken);
    if (this.clock() - principal.verifiedAt >= 600000)
      throw new Failure('FRESH_AUTH_REQUIRED', 403);
    return principal;
  }
  async logout(accessToken: string) {
    const principal = await this.authorize(accessToken);
    await this.db.query('UPDATE native_sessions SET revoked_at=$2 WHERE id=$1', [
      principal.sessionId,
      this.clock(),
    ]);
  }
}
/** Lifecycle invalidation survives unblocking and prevents pending handoff redemption. */
export async function invalidateNativeSessions(tx: QueryDatabase, owner: string, now: number) {
  await tx.query(
    'UPDATE native_sessions SET revoked_at=$2 WHERE owner_id=$1 AND revoked_at IS NULL',
    [owner, now],
  );
  await tx.query('DELETE FROM native_auth_transactions WHERE owner_id=$1', [owner]);
}
