import type { Database } from '../shared/database';
import { RunnerAuthorization } from '../signing/runner-authorization';
/** Missing broker credentials disable the internal endpoint without blocking the public runtime. */
export function createRunnerAuthorizer(
  db: Database,
  now: () => number,
  audience: string,
  proofKey?: string,
) {
  return proofKey && /^[a-f0-9]{64}$/.test(proofKey)
    ? new RunnerAuthorization(db, now, audience, Buffer.from(proofKey, 'hex'))
    : undefined;
}
