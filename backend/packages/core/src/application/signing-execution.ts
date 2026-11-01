import type { QueryDatabase } from '../shared/database';
type ExecutionStorage = {
  objects: { free(required?: number): Promise<void> };
  cleanup(): Promise<void>;
};
type ExecutionArtifacts = {
  reserveJob(owner: string, job: string): Promise<unknown>;
  discardAttempt(owner: string, job: string): Promise<unknown>;
  cleanup(): Promise<void>;
};
export class SigningExecution {
  constructor(
    private db: QueryDatabase,
    private storage: ExecutionStorage,
    private artifacts: ExecutionArtifacts,
    private kickoff: ((owner: string, job: string, device: string) => Promise<unknown>) | undefined,
    private retire?: (nonce: string) => Promise<void>,
  ) {}
  async run(owner: string, job: string, device: string) {
    await this.storage.objects.free(13 * 1024 ** 3);
    await this.artifacts.reserveJob(owner, job);
    try {
      return await this.kickoff!(owner, job, device);
    } finally {
      if (
        !(
          await this.db.query(
            "SELECT id FROM jobs WHERE id=$1 AND state IN('analyzing','provisioning','signing','verifying')",
            [job],
          )
        ).rows.length
      )
        await this.artifacts.discardAttempt(owner, job);
      await this.artifacts.cleanup();
      await this.storage.cleanup();
    }
  }
  async retireLaunch(nonce: string) {
    await this.retire!(nonce);
    const job = (
      await this.db.query<{ owner_id: string; id: string }>(
        'SELECT owner_id,id FROM jobs WHERE lease_token=$1',
        [nonce],
      )
    ).rows[0];
    if (job) await this.artifacts.discardAttempt(job.owner_id, job.id);
  }
}
