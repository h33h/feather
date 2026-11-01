import type { Database } from '../shared/database';
import { Failure } from '../shared/errors';
type JobKickoff = (owner: string, job: string, device: string) => Promise<unknown>;
type Candidate = {
  id: string;
  owner_id: string;
  device_id: string;
  attempts: number;
  valid: boolean;
  source_ready: boolean;
};
const select = `SELECT j.id,j.owner_id,j.device_id,j.attempts,
 EXISTS(SELECT 1 FROM signing_jobs current JOIN signing_devices d ON d.id=current.device_id AND d.owner_id=current.owner_id JOIN apple_connections c ON c.id=current.connection_id AND c.owner_id=current.owner_id WHERE current.id=j.id AND c.state='ready' AND d.status='ready' AND d.connection_generation=c.generation AND current.connection_generation=c.generation) AS valid,
 EXISTS(SELECT 1 FROM uploads u WHERE u.id=j.upload_id AND u.owner_id=j.owner_id AND u.delete_requested_at IS NULL AND u.expires_at>$1 AND u.status IN('ready','uploaded')) AS source_ready
 FROM jobs j WHERE j.state='queued' AND j.next_attempt_at<=$1`;
export class QueuedDispatcher {
  private inFlight: Promise<void> | undefined;
  constructor(
    private db: Database,
    private now: () => number,
    private kickoff?: JobKickoff,
  ) {}
  private async fail(row: Candidate, code: string) {
    await this.db.transaction(async (tx) => {
      const changed = await tx.query(
        "UPDATE jobs SET state='failed',reason=$3,finished_at=$4,updated_at=$4 WHERE id=$1 AND owner_id=$2 AND state='queued' AND attempts=$5 RETURNING upload_id",
        [row.id, row.owner_id, code, this.now(), row.attempts],
      );
      if (changed.rows.length)
        await tx.query(
          'UPDATE uploads SET delete_requested_at=$3 WHERE id IN(SELECT upload_id FROM jobs WHERE id=$1 AND owner_id=$2)',
          [row.id, row.owner_id, this.now()],
        );
    });
  }
  private async schedule(row: Candidate) {
    if (this.inFlight) return false;
    if (!row.source_ready) {
      await this.fail(row, 'SOURCE_EXPIRED');
      return false;
    }
    if (!row.valid) {
      await this.fail(row, 'SIGNING_INPUT_NOT_READY');
      return false;
    }
    if (!this.kickoff) {
      await this.fail(row, 'ISOLATED_RUNNER_NOT_CONFIGURED');
      return false;
    }
    const work = Promise.resolve()
      .then(() => this.kickoff!(row.owner_id, row.id, row.device_id))
      .then(() => {})
      .catch(async (error) => {
        if (error instanceof Failure && error.code === 'RUNNER_BUSY') return;
        await this.fail(row, error instanceof Failure ? error.code : 'RUNNER_START_FAILED');
      })
      .finally(() => {
        if (this.inFlight === work) this.inFlight = undefined;
      });
    this.inFlight = work;
    return true;
  }
  async dispatch() {
    if (this.inFlight) return { scheduled: 0, inFlight: 1 };
    if (
      (
        await this.db.query(
          "SELECT id FROM jobs WHERE state IN('analyzing','provisioning','signing','verifying') LIMIT 1",
        )
      ).rows.length
    )
      return { scheduled: 0, inFlight: 0 };
    const rows = (
      await this.db.query<Candidate>(select + ' ORDER BY j.created_at,j.id LIMIT 20', [this.now()])
    ).rows;
    for (const row of rows) if (await this.schedule(row)) return { scheduled: 1, inFlight: 1 };
    return { scheduled: 0, inFlight: 0 };
  }
  async trigger(_owner: string, _job: string) {
    const result = await this.dispatch();
    return { scheduled: result.scheduled > 0 };
  }
  async drain() {
    await this.inFlight;
  }
}
