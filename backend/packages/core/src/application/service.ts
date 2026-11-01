import type { ExecutorGrant } from '../shared/runner-contracts';
import type { Database } from '../shared/database';
import { SessionService } from '../auth/sessions';
import { DeviceActions } from '../devices/actions';
import { ConnectionLifecycle } from '../apple/connection-lifecycle';
import { AccountLifecycle } from '../auth/account-lifecycle';
import { JobLifecycle } from '../signing/job-lifecycle';
export { Failure, hash, token, id, LIMITS } from '../shared';
export type { Login } from '../auth/sessions';
export type ServiceAdapters = {
  now: () => number;
};
export class Service {
  readonly sessions: SessionService;
  readonly devices: DeviceActions;
  readonly apple: ConnectionLifecycle;
  readonly accounts: AccountLifecycle;
  readonly jobs: JobLifecycle;
  constructor(
    public db: Database,
    adapters: ServiceAdapters,
    options: {
      sessions?: SessionService;
      jobs?: JobLifecycle;
    } = {},
  ) {
    this.sessions = options.sessions ?? new SessionService(db, adapters);
    const now = () => this.sessions.now;
    this.jobs = options.jobs ?? new JobLifecycle(db, now);
    this.devices = new DeviceActions(db, now);
    this.apple = new ConnectionLifecycle(db, now, this.sessions);
    this.accounts = new AccountLifecycle(db, now, this.sessions);
  }
  get now() {
    return this.sessions.now;
  }
  session(raw: string) {
    return this.sessions.session(raw);
  }
  authorizeWrite(raw: string, csrf: string, origin: string, expectedOrigin: string) {
    return this.sessions.authorizeWrite(raw, csrf, origin, expectedOrigin);
  }
  fresh(raw: string, csrf: string, origin: string, expected: string) {
    return this.sessions.fresh(raw, csrf, origin, expected);
  }
  logout(raw: string) {
    return this.sessions.logout(raw);
  }
  selectDevice(ownerId: string, deviceId: string) {
    return this.devices.selectDevice(ownerId, deviceId);
  }
  removeDevice(ownerId: string, deviceId: string) {
    return this.devices.removeDevice(ownerId, deviceId);
  }
  disconnect(raw: string, csrf: string, origin: string, expected: string) {
    return this.apple.disconnect(raw, csrf, origin, expected);
  }
  deleteAccount(raw: string, csrf: string, origin: string, expected: string) {
    return this.accounts.deleteAccount(raw, csrf, origin, expected);
  }
  enqueue(ownerId: string, uploadId: string, key: string) {
    return this.jobs.enqueue(ownerId, uploadId, key);
  }
  claim(jobId: string, ownerId: string) {
    return this.jobs.claim(jobId, ownerId);
  }
  heartbeat(jobId: string, ownerId: string, lease: string) {
    return this.jobs.heartbeat(jobId, ownerId, lease);
  }
  deferBusy(lease: Pick<ExecutorGrant, 'ownerId' | 'jobId' | 'leaseToken'>) {
    return this.jobs.deferBusy(lease);
  }
  finishAttempt(
    lease: Pick<ExecutorGrant, 'ownerId' | 'jobId' | 'leaseToken'>,
    outcome: { code?: string; cancelled?: boolean },
  ) {
    return this.jobs.finishAttempt(lease, outcome);
  }
  recoverLeases(
    retireExecutor?: (grant: ExecutorGrant) => Promise<void>,
    retireLaunch?: (nonce: string) => Promise<void>,
  ) {
    return this.jobs.recoverLeases(retireExecutor, retireLaunch);
  }
}
