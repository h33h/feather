import type { QueryDatabase } from '../shared/database';

export function artifactDeadline(
  readyAt: number,
  certificateExpiresAt: number,
  profileExpiresAt: number,
) {
  return Math.min(readyAt + 1800000, certificateExpiresAt, profileExpiresAt);
}
export async function scheduleTerminalCleanup(tx: QueryDatabase, jobId: string, now: number) {
  await tx.query(
    "UPDATE uploads SET delete_requested_at=$2 WHERE id IN(SELECT upload_id FROM jobs WHERE id=$1 AND state IN('ready','failed','cancelled'))",
    [jobId, now],
  );
}
