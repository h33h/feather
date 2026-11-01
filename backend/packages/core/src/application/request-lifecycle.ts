import type { Service } from './service';
import type { JobsActions } from '../signing/jobs-actions';
import { Failure } from '../shared';
type Cleanup = { cleanup(): Promise<void> };
export class RequestLifecycle {
  constructor(
    private service: Pick<Service, 'deleteAccount'> & Partial<Pick<Service, 'accounts'>>,
    private jobs: Pick<JobsActions, 'cancel'>,
    private storage: Cleanup,
    private artifacts: Cleanup,
  ) {}
  async cancel(owner: string, job: string) {
    const result = await this.jobs.cancel(owner, job);
    await this.storage.cleanup();
    await this.artifacts.cleanup();
    return result;
  }
  async deleteAccount(raw: string, csrf: string, origin: string, expected: string) {
    await this.service.deleteAccount(raw, csrf, origin, expected);
    await this.storage.cleanup();
    await this.artifacts.cleanup();
  }
  async deleteAccountFor(owner: string) {
    if (!this.service.accounts) throw new Failure('ACCOUNT_LIFECYCLE_UNAVAILABLE', 503);
    await this.service.accounts.removeProfile(owner);
    await this.storage.cleanup();
    await this.artifacts.cleanup();
  }
}
