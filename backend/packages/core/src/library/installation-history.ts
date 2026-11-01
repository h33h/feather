import type { Database } from '../shared/database';
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
