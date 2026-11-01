import type { Database, QueryDatabase } from '../shared/database';
import { Failure } from '../shared/errors';
import type { SigningWarning } from '../shared/signing-contracts';
export type HistoryStatus = 'ready' | 'failed' | 'cancelled';
export type InstallationHistoryItem = {
  id: string;
  name: string;
  version: string | null;
  finishedAt: number;
  state: HistoryStatus;
  error: string | null;
  warnings: SigningWarning[];
};
export type HistoryPage = { items: InstallationHistoryItem[]; nextCursor: string | null };
export class InstallationHistory {
  constructor(
    private db: QueryDatabase,
    private now: () => number,
  ) {}
  async list(
    owner: string,
    input: { cursor?: string; limit?: number; status?: HistoryStatus } = {},
  ): Promise<HistoryPage> {
    const limit = input.limit ?? 30;
    if (!Number.isInteger(limit) || limit < 1 || limit > 100)
      throw new Failure('INVALID_HISTORY_LIMIT');
    if (input.status && !['ready', 'failed', 'cancelled'].includes(input.status))
      throw new Failure('INVALID_HISTORY_STATUS');
    let cursor: { owner: string; finishedAt: number; id: string } | undefined;
    if (input.cursor) {
      try {
        cursor = JSON.parse(Buffer.from(input.cursor, 'base64url').toString());
        if (
          !cursor ||
          cursor.owner !== owner ||
          !Number.isSafeInteger(cursor.finishedAt) ||
          typeof cursor.id !== 'string' ||
          cursor.id.length > 100 ||
          input.cursor.length > 1024
        )
          throw Error();
      } catch {
        throw new Failure('INVALID_HISTORY_CURSOR');
      }
    }
    const rows = (
      await this.db.query<InstallationHistoryItem>(
        `SELECT j.id,COALESCE(j.display_snapshot->>'name','Приложение') AS name,j.display_snapshot->>'version' AS version,j.finished_at AS "finishedAt",j.state,j.reason AS error,j.warnings
    FROM jobs j JOIN users u ON u.id=j.owner_id WHERE j.owner_id=$1 AND u.deleted_at IS NULL AND u.blocked_at IS NULL
    AND j.state IN('ready','failed','cancelled') AND j.finished_at>$2 AND j.display_snapshot IS NOT NULL
    AND ($3::text IS NULL OR j.state=$3) AND ($4::bigint IS NULL OR (j.finished_at,j.id)<($4,$5))
    ORDER BY j.finished_at DESC,j.id DESC LIMIT $6`,
        [
          owner,
          this.now() - 2592000000,
          input.status ?? null,
          cursor?.finishedAt ?? null,
          cursor?.id ?? null,
          limit + 1,
        ],
      )
    ).rows;
    const items = rows
      .slice(0, limit)
      .map((row) => ({ ...row, finishedAt: Number(row.finishedAt) }));
    const last = items.at(-1);
    return {
      items,
      nextCursor:
        rows.length > limit && last
          ? Buffer.from(
              JSON.stringify({ owner, finishedAt: last.finishedAt, id: last.id }),
            ).toString('base64url')
          : null,
    };
  }
}
export async function cleanupHistory(db: Database, now: number) {
  await db.transaction(async (tx) => {
    const jobs = (
      await tx.query<{ id: string; upload_id: string }>(
        "SELECT id,upload_id FROM jobs WHERE state IN('ready','failed','cancelled') AND finished_at<=$1 FOR UPDATE",
        [now - 2592000000],
      )
    ).rows;
    for (const job of jobs) {
      await tx.query(
        "UPDATE personal_objects SET state='deleting' WHERE job_id=$1 OR object_key IN(SELECT object_key FROM uploads WHERE id=$2)",
        [job.id, job.upload_id],
      );
      await tx.query(
        'DELETE FROM tickets WHERE artifact_id IN(SELECT id FROM artifacts WHERE job_id=$1)',
        [job.id],
      );
      await tx.query('DELETE FROM executor_tasks WHERE job_id=$1', [job.id]);
      await tx.query('DELETE FROM artifacts WHERE job_id=$1', [job.id]);
      await tx.query('UPDATE personal_objects SET job_id=NULL WHERE job_id=$1', [job.id]);
      await tx.query('DELETE FROM jobs WHERE id=$1', [job.id]);
      await tx.query('DELETE FROM imports WHERE upload_id=$1', [job.upload_id]);
      await tx.query(
        'DELETE FROM uploads WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM jobs WHERE upload_id=$1)',
        [job.upload_id],
      );
    }
  });
}
