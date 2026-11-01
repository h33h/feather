import type { AccountLifecycle } from '../auth/account-lifecycle';
type Cleanup = { cleanup(): Promise<void> };
export class RequestLifecycle {
  constructor(
    private accounts: Pick<AccountLifecycle, 'removeProfile'>,
    private storage: Cleanup,
    private artifacts: Cleanup,
  ) {}
  async deleteAccountFor(owner: string) {
    await this.accounts.removeProfile(owner);
    await this.storage.cleanup();
    await this.artifacts.cleanup();
  }
}
