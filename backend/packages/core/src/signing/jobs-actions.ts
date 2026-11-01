import type { Database } from '../shared/database';
import { Failure } from '../shared/errors';
import { lockAuthority } from '../apple/access-lifecycle';
import { JobLifecycle } from './job-lifecycle';
export type JobKickoff = (ownerId: string, jobId: string, deviceId: string) => Promise<unknown>;
export type JobActionResult = {
  id: string;
  state: string;
  reason: string | null;
  artifactId?: string;
  reused?: boolean;
};
export class JobsActions {
  readonly queue: JobLifecycle;
  constructor(
    private db: Database,
    private now: () => number,
    private kickoff?: JobKickoff,
  ) {
    this.queue = new JobLifecycle(db, now);
  }
  private async result(owner: string, job: string): Promise<JobActionResult> {
    const row = (
      await this.db.query<JobActionResult>(
        'SELECT id,state,reason FROM jobs WHERE id=$1 AND owner_id=$2',
        [job, owner],
      )
    ).rows[0];
    if (!row) throw new Failure('NOT_FOUND', 404);
    return row;
  }
  private notify(owner: string, job: string, device: string) {
    if (this.kickoff)
      void Promise.resolve()
        .then(() => this.kickoff!(owner, job, device))
        .catch(() => {});
  }
  async ensure(
    owner: string,
    input: {
      uploadId: string;
      deviceId?: string;
      key: string;
    },
  ): Promise<JobActionResult> {
    const result = await this.queue.enqueue(owner, input.uploadId, input.key, input.deviceId);
    if (result.created) {
      const selected = (
        await this.db.query<{ device_id: string }>(
          'SELECT device_id FROM jobs WHERE id=$1 AND owner_id=$2',
          [result.id, owner],
        )
      ).rows[0];
      this.notify(owner, result.id, selected.device_id);
    }
    return this.result(owner, result.id);
  }
  async beginSubmission(owner: string, input: Parameters<JobLifecycle['beginSubmission']>[1]) {
    return this.queue.beginSubmission(owner, input);
  }
  async completeSource(owner: string, job: string) {
    await this.queue.completeSource(owner, job);
    const selected = (
      await this.db.query<{ device_id: string }>(
        'SELECT device_id FROM jobs WHERE id=$1 AND owner_id=$2',
        [job, owner],
      )
    ).rows[0];
    this.notify(owner, job, selected.device_id);
  }
  async cancel(owner: string, job: string) {
    await this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      const active = await tx.query(
        'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
        [owner],
      );
      if (!active.rows.length) throw new Failure('USER_UNAVAILABLE', 404);
      const updated = await tx.query(
        "UPDATE jobs SET state='cancelled',reason='USER_CANCELLED',finished_at=$3,updated_at=$3,lease_token=NULL,lease_expires=NULL WHERE id=$1 AND owner_id=$2 AND state IN('receiving','queued','analyzing','provisioning','signing','verifying') RETURNING upload_id",
        [job, owner, this.now()],
      );
      if (!updated.rows.length) {
        const existing = await tx.query('SELECT id FROM jobs WHERE id=$1 AND owner_id=$2', [
          job,
          owner,
        ]);
        if (!existing.rows.length) throw new Failure('NOT_FOUND', 404);
        return;
      }
      await tx.query('UPDATE executor_tasks SET consumed=true WHERE job_id=$1 AND owner_id=$2', [
        job,
        owner,
      ]);
      await tx.query(
        'UPDATE uploads SET delete_requested_at=$3 WHERE id IN(SELECT upload_id FROM jobs WHERE id=$1 AND owner_id=$2)',
        [job, owner, this.now()],
      );
    });
    return this.result(owner, job);
  }
  async retry(owner: string, job: string): Promise<JobActionResult> {
    await this.result(owner, job);
    throw new Failure('SOURCE_RELOAD_REQUIRED', 410);
  }
}
