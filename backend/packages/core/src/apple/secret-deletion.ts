import type { Database } from '../shared/database';
import type { Vault } from './vault';
import { token } from '../shared/index';
/** Retries durable secret tombstones. Must be bound to a restore-independent KMS revocation ledger. */
export class SecretDeletionWorker {
  constructor(
    private db: Database,
    private vault: Vault,
    private now: () => number,
  ) {}
  async runOne() {
    const lease = token();
    const rows = await this.db.query<{
      id: string;
      owner_id: string;
      secret_id: string;
    }>(
      'UPDATE secret_deletions SET lease_token=$1,lease_expires=$2,attempts=attempts+1 WHERE id=(SELECT id FROM secret_deletions WHERE completed_at IS NULL AND (lease_expires IS NULL OR lease_expires<=$3) ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING id,owner_id,secret_id',
      [lease, this.now() + 60000, this.now()],
    );
    const row = rows.rows[0];
    if (!row) return false;
    try {
      await this.vault.tombstone(row.owner_id, row.secret_id);
      await this.db.query(
        'UPDATE secret_deletions SET completed_at=$3,lease_token=NULL,lease_expires=NULL WHERE id=$1 AND lease_token=$2',
        [row.id, lease, this.now()],
      );
      return true;
    } catch {
      await this.db.query(
        'UPDATE secret_deletions SET lease_token=NULL,lease_expires=$3 WHERE id=$1 AND lease_token=$2',
        [row.id, lease, this.now() + 60000],
      );
      return false;
    }
  }
}
