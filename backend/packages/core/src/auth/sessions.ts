import type { QueryDatabase } from '../shared/database';
import { Failure, hash } from '../shared/index';
export interface Login {
  ownerId: string;
  token: string;
  csrf: string;
  verifiedAt: number;
  expiresAt: number;
}
export class SessionService {
  constructor(
    public db: QueryDatabase,
    private adapters: { now: () => number },
  ) {}
  get now() {
    return this.adapters.now();
  }
  async session(raw: string) {
    const row = (
      await this.db.query<{
        owner_id: string;
        csrf_hash: string;
        verified_at: number;
        expires_at: number;
        role: 'user' | 'admin';
        login_name: string;
        public_profile_id: string;
      }>(
        'SELECT s.owner_id,s.csrf_hash,s.verified_at,s.expires_at,u.role,u.login_name,u.public_profile_id FROM sessions s JOIN users u ON u.id=s.owner_id WHERE s.token_hash=$1 AND s.expires_at>$2 AND u.deleted_at IS NULL AND u.blocked_at IS NULL',
        [hash(raw), this.now],
      )
    ).rows[0];
    if (!row) throw new Failure('UNAUTHENTICATED', 401);
    return {
      ownerId: row.owner_id,
      csrfHash: row.csrf_hash,
      verifiedAt: Number(row.verified_at),
      expiresAt: Number(row.expires_at),
      role: row.role,
      loginName: row.login_name,
      publicProfileId: row.public_profile_id,
    };
  }
  async authorizeWrite(raw: string, csrf: string, origin: string, expectedOrigin: string) {
    const session = await this.session(raw);
    if (origin !== expectedOrigin || !csrf || hash(csrf) !== session.csrfHash)
      throw new Failure('CSRF', 403);
    return session;
  }
  async fresh(raw: string, csrf: string, origin: string, expected: string) {
    const session = await this.authorizeWrite(raw, csrf, origin, expected);
    if (this.now - session.verifiedAt >= 600000) throw new Failure('FRESH_AUTH_REQUIRED', 403);
    return session;
  }
  async logout(raw: string) {
    await this.db.query('DELETE FROM sessions WHERE token_hash=$1', [hash(raw)]);
  }
}
