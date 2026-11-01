import type { QueryDatabase } from '../shared/database';
import { Failure } from '../shared/errors';
export class SigningReadiness {
  constructor(
    private db: QueryDatabase,
    private bootstrap: ((owner: string) => Promise<unknown>) | undefined,
    private collections: { reconcileOwner(owner: string): Promise<unknown> },
    private now: () => number,
  ) {}
  async ensure(owner: string) {
    const row = (
      await this.db.query<{ owner: string; expires: number | null; ready: boolean }>(
        "SELECT c.connection_owner_id AS owner,(b.certificate->>'expiresAt')::bigint AS expires,EXISTS(SELECT 1 FROM secrets s WHERE s.id=b.identity->>'secretRef' AND s.deleted_at IS NULL) AS ready FROM apple_connections c LEFT JOIN bootstrap_operations b ON b.owner_id=c.connection_owner_id AND b.connection_id=c.id AND b.generation=c.generation AND b.certificate_state='committed' WHERE c.owner_id=$1 AND c.state='ready'",
        [owner],
      )
    ).rows[0];
    if (row && (!row.ready || !row.expires || Number(row.expires) <= this.now())) {
      if (!this.bootstrap) throw new Failure('BOOTSTRAP_BROKER_UNAVAILABLE', 503);
      await this.bootstrap(row.owner);
      await this.collections.reconcileOwner(owner);
    }
  }
}
