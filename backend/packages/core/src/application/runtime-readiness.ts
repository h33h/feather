import type { QueryDatabase } from '../shared/database';
import { Failure } from '../shared/errors';
export class RuntimeReadiness {
  constructor(
    private db: QueryDatabase,
    private kms: { assertReady(): Promise<unknown> },
    private kickoff: unknown,
    private checkReady: (() => Promise<unknown>) | undefined,
    private bootstrap: unknown,
  ) {}
  async check() {
    await this.db.query('SELECT 1');
    await this.kms.assertReady();
    if (!this.kickoff || !this.checkReady || !this.bootstrap)
      throw new Failure('NATIVE_PIPELINE_UNAVAILABLE', 503);
    await this.checkReady();
  }
}
