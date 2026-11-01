import { invalidateNativeSessions } from './native-sessions';
import { isIP } from 'node:net';
import { invalidateAccess, lockAuthority } from '../apple/access-lifecycle';
import { lockPrincipalConnections } from '../apple/access';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type RegistrationResponseJSON,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import type { Database, QueryDatabase } from '../shared/database';
import { Failure, hash, id, token } from '../shared/index';
import type { Login } from './sessions';
type Challenge = {
  id: string;
  challenge: string;
  kind: string;
  owner_id: string | null;
  invite_hash: string | null;
  session_hash: string | null;
  expires_at: number;
};
type Credential = {
  id: string;
  owner_id: string;
  public_key: string;
  counter: number;
  transports: string[];
};
/** Invites are operator-created. No self registration and no email fallback. */
export class PersonalAuth {
  readonly rpId: string;
  constructor(
    public db: Database,
    public origin: string,
    private clock = Date.now,
  ) {
    const url = new URL(origin);
    if (isIP(url.hostname.replace(/^\[|\]$/g, '')))
      throw new Failure('PASSKEY_ORIGIN_DOMAIN_REQUIRED', 503);
    if (
      !(url.protocol === 'https:' || (url.protocol === 'http:' && url.hostname === 'localhost')) ||
      url.origin !== origin
    )
      throw new Failure('PASSKEY_HTTPS_REQUIRED', 503);
    this.rpId = url.hostname;
  }
  private async lock(tx: QueryDatabase) {
    await tx.query('SELECT id FROM personal_state WHERE id=1 FOR UPDATE');
  }
  private invalid() {
    return new Failure('PASSKEY_AUTH_FAILED', 401);
  }
  async rate(scope: string) {
    await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.lock(tx);
      await tx.query('DELETE FROM auth_limits WHERE window_start<=$1', [this.clock() - 60000]);
      const count = await tx.query<{
        count: number;
      }>('SELECT count FROM auth_limits WHERE key=$1', [hash(scope)]);
      if (Number(count.rows[0]?.count ?? 0) >= 30) throw new Failure('AUTH_RATE_LIMITED', 429);
      if ((await tx.query('SELECT key FROM auth_limits LIMIT 1001')).rows.length > 1000)
        throw new Failure('AUTH_RATE_LIMITED', 429);
      await tx.query(
        'INSERT INTO auth_limits(key,window_start,count) VALUES($1,$2,1) ON CONFLICT(key) DO UPDATE SET count=auth_limits.count+1',
        [hash(scope), this.clock()],
      );
      await tx.query('DELETE FROM passkey_challenges WHERE expires_at<=$1', [this.clock()]);
    });
  }
  async invite(name: string) {
    if (!/^[a-zA-Z0-9_-]{1,40}$/.test(name)) throw new Failure('LOGIN_NAME_INVALID');
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.lock(tx);
      const ownerId = id();
      await tx.query('INSERT INTO users(id,login_name,created_at) VALUES($1,$2,$3)', [
        ownerId,
        name,
        this.clock(),
      ]);
      return { ownerId, ...(await this.issueInvite(tx, ownerId)) };
    });
  }
  /** Operator-only creation of the first administrator on a clean installation. */
  async bootstrapAdmin(name: string) {
    if (!/^[a-zA-Z0-9_-]{1,40}$/.test(name)) throw new Failure('LOGIN_NAME_INVALID');
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.lock(tx);
      if ((await tx.query('SELECT id FROM users LIMIT 1')).rows.length)
        throw new Failure('ADMIN_ALREADY_INITIALIZED', 409);
      const ownerId = id();
      await tx.query("INSERT INTO users(id,login_name,role,created_at) VALUES($1,$2,'admin',$3)", [
        ownerId,
        name,
        this.clock(),
      ]);
      return { ownerId, ...(await this.issueInvite(tx, ownerId)) };
    });
  }
  private async issueInvite(tx: QueryDatabase, owner: string) {
    return issueInvitation(tx, owner, this.clock());
  }
  async operatorReinvite(owner: string) {
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.lock(tx);
      await lockPrincipalConnections(tx, owner);
      if (
        !(
          await tx.query(
            'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
            [owner],
          )
        ).rows.length
      )
        throw this.invalid();
      await this.revokeAccess(tx, owner);
      return this.issueInvite(tx, owner);
    });
  }
  private async challenge(
    kind: string,
    challenge: string,
    owner: string | null,
    invite: string | null,
    session: string | null,
  ) {
    const requestId = token();
    await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.lock(tx);
      if (
        (
          await tx.query(
            'SELECT id FROM passkey_challenges WHERE expires_at>$1 AND consumed_at IS NULL LIMIT 101',
            [this.clock()],
          )
        ).rows.length >= 100
      )
        throw new Failure('AUTH_RATE_LIMITED', 429);
      await tx.query(
        'INSERT INTO passkey_challenges(id,challenge,kind,owner_id,invite_hash,session_hash,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)',
        [hash(requestId), challenge, kind, owner, invite, session, this.clock() + 300000],
      );
    });
    return requestId;
  }
  async registrationOptions(invite: string) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(invite)) throw this.invalid();
    const rows = await this.db.query<{
      owner_id: string;
      login_name: string;
    }>(
      'SELECT i.owner_id,u.login_name FROM passkey_invites i JOIN users u ON u.id=i.owner_id WHERE i.token_hash=$1 AND i.expires_at>$2 AND i.consumed_at IS NULL AND u.deleted_at IS NULL AND u.blocked_at IS NULL',
      [hash(invite), this.clock()],
    );
    const row = rows.rows[0];
    if (!row) throw this.invalid();
    const options = await generateRegistrationOptions({
      rpName: 'iSign',
      rpID: this.rpId,
      userName: row.login_name,
      userID: Buffer.from(row.owner_id),
      supportedAlgorithmIDs: [-7, -257],
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      timeout: 300000,
    });
    return {
      requestId: await this.challenge(
        'register',
        options.challenge,
        row.owner_id,
        hash(invite),
        null,
      ),
      options,
    };
  }
  async addOptions(owner: string, raw: string) {
    const row = await this.db.query<{
      login_name: string;
    }>(
      'SELECT u.login_name FROM users u JOIN sessions s ON s.owner_id=u.id WHERE u.id=$1 AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND s.token_hash=$2 AND s.expires_at>$3 AND s.verified_at>$3-600000',
      [owner, hash(raw), this.clock()],
    );
    if (!row.rows[0]) throw new Failure('FRESH_AUTH_REQUIRED', 403);
    const keys = await this.db.query<Credential>('SELECT * FROM passkeys WHERE owner_id=$1', [
      owner,
    ]);
    if (keys.rows.length >= 5) throw new Failure('PASSKEY_LIMIT', 409);
    const options = await generateRegistrationOptions({
      rpName: 'iSign',
      rpID: this.rpId,
      userName: row.rows[0].login_name,
      userID: Buffer.from(owner),
      supportedAlgorithmIDs: [-7, -257],
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      excludeCredentials: keys.rows.map((k) => ({ id: k.id, transports: k.transports })),
    });
    return {
      requestId: await this.challenge('add', options.challenge, owner, null, hash(raw)),
      options,
    };
  }
  private async take(tx: QueryDatabase, requestId: string, kinds: string[]) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(requestId)) throw this.invalid();
    const row = (
      await tx.query<Challenge>(
        'SELECT * FROM passkey_challenges WHERE id=$1 AND consumed_at IS NULL AND expires_at>$2 FOR UPDATE',
        [hash(requestId), this.clock()],
      )
    ).rows[0];
    if (!row || !kinds.includes(row.kind)) throw this.invalid();
    await tx.query('UPDATE passkey_challenges SET consumed_at=$2 WHERE id=$1', [
      row.id,
      this.clock(),
    ]);
    return row;
  }
  private async session(tx: QueryDatabase, owner: string): Promise<Login> {
    const result = {
      ownerId: owner,
      token: token(),
      csrf: token(),
      verifiedAt: this.clock(),
      expiresAt: this.clock() + 7 * 86400000,
    };
    await tx.query(
      'INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,$2,$3,$4,$5)',
      [hash(result.token), owner, hash(result.csrf), result.verifiedAt, result.expiresAt],
    );
    return result;
  }
  async register(requestId: string, response: RegistrationResponseJSON, raw = '') {
    const challenge = await this.db.transaction((tx) =>
      this.take(tx, requestId, ['register', 'add']),
    );
    let verified;
    try {
      verified = await verifyRegistrationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        requireUserPresence: true,
        requireUserVerification: true,
        supportedAlgorithmIDs: [-7, -257],
      });
    } catch {
      throw this.invalid();
    }
    if (!verified.verified || !verified.registrationInfo.userVerified || !challenge.owner_id)
      throw this.invalid();
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      await this.lock(tx);
      if (Number(challenge.expires_at) <= this.clock()) throw this.invalid();
      const owner = challenge.owner_id!;
      if (
        !(
          await tx.query(
            'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
            [owner],
          )
        ).rows.length
      )
        throw this.invalid();
      if (challenge.kind === 'register') {
        const used = await tx.query(
          'UPDATE passkey_invites SET consumed_at=$3 WHERE token_hash=$1 AND owner_id=$2 AND consumed_at IS NULL AND expires_at>$3 RETURNING token_hash',
          [challenge.invite_hash, owner, this.clock()],
        );
        if (!used.rows.length) throw this.invalid();
        if ((await tx.query('SELECT id FROM passkeys WHERE owner_id=$1', [owner])).rows.length)
          throw this.invalid();
      } else {
        if (
          challenge.session_hash !== hash(raw) ||
          !(
            await tx.query(
              'SELECT token_hash FROM sessions WHERE token_hash=$1 AND owner_id=$2 AND expires_at>$3 AND verified_at>$3-600000',
              [hash(raw), owner, this.clock()],
            )
          ).rows.length
        )
          throw this.invalid();
        if ((await tx.query('SELECT id FROM passkeys WHERE owner_id=$1', [owner])).rows.length >= 5)
          throw new Failure('PASSKEY_LIMIT', 409);
      }
      const credential = verified.registrationInfo.credential;
      await tx.query(
        'INSERT INTO passkeys(id,owner_id,public_key,counter,transports,created_at) VALUES($1,$2,$3,$4,$5,$6)',
        [
          credential.id,
          owner,
          Buffer.from(credential.publicKey).toString('base64'),
          credential.counter,
          JSON.stringify(response.response.transports ?? []),
          this.clock(),
        ],
      );
      return this.session(tx, owner);
    });
  }
  async authenticationOptions(owner?: string, raw?: string) {
    if (
      owner &&
      (!raw ||
        !(
          await this.db.query(
            'SELECT token_hash FROM sessions s JOIN users u ON u.id=s.owner_id WHERE s.token_hash=$1 AND s.owner_id=$2 AND s.expires_at>$3 AND u.deleted_at IS NULL AND u.blocked_at IS NULL',
            [hash(raw), owner, this.clock()],
          )
        ).rows.length)
    )
      throw this.invalid();
    const keys = owner
      ? (await this.db.query<Credential>('SELECT * FROM passkeys WHERE owner_id=$1', [owner])).rows
      : undefined;
    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      userVerification: 'required',
      timeout: 300000,
      ...(keys
        ? { allowCredentials: keys.map((k) => ({ id: k.id, transports: k.transports as never })) }
        : {}),
    });
    return {
      requestId: await this.challenge(
        owner ? 'fresh' : 'login',
        options.challenge,
        owner ?? null,
        null,
        raw ? hash(raw) : null,
      ),
      options,
    };
  }
  async authenticate(requestId: string, response: AuthenticationResponseJSON, raw = '') {
    const challenge = await this.db.transaction((tx) =>
      this.take(tx, requestId, ['login', 'fresh']),
    );
    return this.db.transaction(async (tx) => {
      if (Number(challenge.expires_at) <= this.clock()) throw this.invalid();
      const credential = (
        await tx.query<Credential>(
          'SELECT p.* FROM passkeys p JOIN users u ON u.id=p.owner_id WHERE p.id=$1 AND u.deleted_at IS NULL AND u.blocked_at IS NULL FOR UPDATE OF p,u',
          [response.id],
        )
      ).rows[0];
      if (!credential || (challenge.owner_id && challenge.owner_id !== credential.owner_id))
        throw this.invalid();
      if (
        challenge.kind === 'fresh' &&
        (challenge.session_hash !== hash(raw) ||
          !(
            await tx.query(
              'SELECT token_hash FROM sessions WHERE token_hash=$1 AND owner_id=$2 AND expires_at>$3',
              [hash(raw), credential.owner_id, this.clock()],
            )
          ).rows.length)
      )
        throw this.invalid();
      let verified;
      try {
        verified = await verifyAuthenticationResponse({
          response,
          expectedChallenge: challenge.challenge,
          expectedOrigin: this.origin,
          expectedRPID: this.rpId,
          requireUserVerification: true,
          credential: {
            id: credential.id,
            publicKey: Buffer.from(credential.public_key, 'base64'),
            counter: Number(credential.counter),
            transports: credential.transports as never,
          },
        });
      } catch {
        throw this.invalid();
      }
      if (!verified.verified || !verified.authenticationInfo.userVerified) throw this.invalid();
      await tx.query('UPDATE passkeys SET counter=$2 WHERE id=$1', [
        credential.id,
        verified.authenticationInfo.newCounter,
      ]);
      if (challenge.kind === 'fresh')
        await tx.query('DELETE FROM sessions WHERE token_hash=$1', [hash(raw)]);
      return this.session(tx, credential.owner_id);
    });
  }
  private async revokeAccess(tx: QueryDatabase, owner: string) {
    await resetCredentials(tx, owner, this.clock());
  }
}

export async function issueInvitation(tx: QueryDatabase, owner: string, now: number) {
  const raw = token(),
    expiresAt = now + 900000;
  await tx.query('DELETE FROM passkey_invites WHERE owner_id=$1', [owner]);
  await tx.query('INSERT INTO passkey_invites(token_hash,owner_id,expires_at) VALUES($1,$2,$3)', [
    hash(raw),
    owner,
    expiresAt,
  ]);
  return { token: raw, expiresAt };
}
export async function resetCredentials(tx: QueryDatabase, owner: string, now: number) {
  await invalidateAccess(tx, { userId: owner }, 'AUTH_RECOVERY', now);
  await invalidateNativeSessions(tx, owner, now);
  for (const table of ['sessions', 'passkeys', 'passkey_challenges', 'passkey_invites'])
    await tx.query('DELETE FROM ' + table + ' WHERE owner_id=$1', [owner]);
  await tx.query('UPDATE bootstrap_secret_grants SET consumed=true WHERE owner_id=$1', [owner]);
}
