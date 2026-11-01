import { assertAppleAccess } from '../apple/access';
import { createHmac } from 'node:crypto';
import type { Database } from '../shared/database';
import { Failure } from '../shared/index';
import type { ExecutorGrant } from '../shared/runner-contracts';
import { canonicalReport } from '../shared/canonical-json';
const allowed = new Set([
  'instance',
  'grant',
  'launch',
  'source',
  'analyze',
  'execute',
  'artifact',
  'destroy',
  'capabilities',
  'device-profile-verify',
  'bootstrap-prepare',
  'material-prepare',
  'bundle-ownership',
  'provision',
  'bootstrap-find-certificates',
  'bootstrap-create-certificate',
]);
/** Read-only control-plane authorization; cleanup is allowed after revocation, private operations are fenced. */
export class RunnerAuthorization {
  constructor(
    private db: Database,
    private now: () => number,
    private audience: string,
    private key: Buffer,
  ) {
    if (key.length < 32) throw new Failure('RUNNER_AUTHORIZATION_UNAVAILABLE', 503);
  }
  async authorize(input: {
    operation: string;
    binding: Record<string, unknown>;
    nonce: string;
    audience: string;
  }) {
    if (
      !allowed.has(input.operation) ||
      input.audience !== this.audience ||
      !/^[A-Za-z0-9_-]{43}$/.test(input.nonce) ||
      !input.binding ||
      typeof input.binding !== 'object' ||
      Array.isArray(input.binding) ||
      Buffer.byteLength(canonicalReport(input.binding)) > 8192
    )
      throw new Failure('RUNNER_AUTHORIZATION_INVALID', 403);
    const b = input.binding;
    let authorized = false;
    if (input.operation === 'capabilities')
      authorized =
        Object.keys(b).length === 1 &&
        typeof b.nonce === 'string' &&
        /^[A-Za-z0-9_-]{43}$/.test(b.nonce);
    else if (input.operation === 'destroy')
      authorized = typeof b.ownerId === 'string' && typeof b.jobId === 'string';
    else if (typeof b.jobId === 'string' && typeof b.ownerId === 'string') {
      if (b.jobId.startsWith('bootstrap:')) {
        const r = await this.db.query(
          "SELECT b.nonce FROM bootstrap_operations b JOIN connections c ON c.id=b.connection_id AND c.owner_id=b.owner_id JOIN users u ON u.id=b.owner_id WHERE b.owner_id=$1 AND b.nonce=$2 AND b.expires_at>$3 AND c.generation=b.generation AND c.state IN('validating','action_required') AND u.deleted_at IS NULL AND u.blocked_at IS NULL",
          [b.ownerId, b.jobId.slice(10), this.now()],
        );
        authorized = r.rows.length > 0;
      } else if (b.jobId.startsWith('device-eligibility:')) {
        const r = await this.db.query(
          "SELECT c.id FROM apple_connections c JOIN users u ON u.id=c.owner_id WHERE c.owner_id=$1 AND c.state='ready' AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL",
          [b.ownerId],
        );
        authorized = r.rows.length > 0;
      } else {
        const r = await this.db.query<{
          binding: ExecutorGrant | null;
        }>(
          "SELECT t.binding FROM signing_jobs j JOIN users u ON u.id=j.owner_id JOIN apple_connections c ON c.id=j.connection_id AND c.owner_id=j.owner_id JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id JOIN uploads x ON x.id=j.upload_id AND x.owner_id=j.owner_id LEFT JOIN executor_tasks t ON t.job_id=j.id AND t.owner_id=j.owner_id AND t.nonce=$4 AND t.consumed=false AND t.expires_at>$3 WHERE j.owner_id=$1 AND j.id=$2 AND j.lease_expires>$3 AND j.state IN('analyzing','provisioning','signing','verifying') AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND c.state='ready' AND c.provider='asc' AND c.generation=j.connection_generation AND d.connection_generation=c.generation AND d.status='ready' AND x.expires_at>$3 AND ($5::text IS NULL OR j.lease_token=$5)",
          [
            b.ownerId,
            b.jobId,
            this.now(),
            typeof b.taskNonce === 'string' ? b.taskNonce : null,
            typeof b.leaseToken === 'string'
              ? b.leaseToken
              : input.operation === 'launch' && typeof b.nonce === 'string'
                ? b.nonce
                : null,
          ],
        );
        authorized = r.rows.length === 1;
        if (authorized && typeof b.taskNonce === 'string')
          authorized =
            !!r.rows[0].binding && canonicalReport(r.rows[0].binding) === canonicalReport(b);
        else if (authorized)
          authorized = ['instance', 'grant', 'launch', 'source', 'artifact'].includes(
            input.operation,
          );
      }
    } else if (
      typeof b.ownerId === 'string' &&
      typeof b.connectionId === 'string' &&
      Number.isInteger(b.generation) &&
      typeof b.nonce === 'string' &&
      Number.isSafeInteger(b.expiresAt) &&
      Number(b.expiresAt) > this.now()
    ) {
      const pending = input.operation.startsWith('bootstrap-');
      const r = await this.db.query(
        pending
          ? "SELECT b.nonce FROM bootstrap_operations b JOIN connections c ON c.id=b.connection_id AND c.owner_id=b.owner_id JOIN users u ON u.id=b.owner_id WHERE b.owner_id=$1 AND b.connection_id=$2 AND b.generation=$3 AND b.nonce=$4 AND b.expires_at=$5 AND b.expires_at>$6 AND c.generation=b.generation AND c.state IN('validating','action_required') AND u.deleted_at IS NULL AND u.blocked_at IS NULL"
          : "SELECT c.id FROM apple_connections c JOIN users u ON u.id=c.owner_id WHERE c.owner_id=$1 AND c.id=$2 AND c.generation=$3 AND c.state='ready' AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND $5::bigint>$6 AND $4::text IS NOT NULL",
        [b.ownerId, b.connectionId, b.generation, b.nonce, b.expiresAt, this.now()],
      );
      authorized = r.rows.length === 1;
      if (authorized && input.operation === 'device-profile-verify') {
        try {
          if (typeof b.connectionOwnerId !== 'string')
            throw new Failure('RUNNER_AUTHORIZATION_INVALID', 403);
          await assertAppleAccess(this.db, {
            ownerId: String(b.ownerId),
            connectionId: String(b.connectionId),
            generation: Number(b.generation),
            connectionOwnerId: b.connectionOwnerId,
            accessGrantId: typeof b.accessGrantId === 'string' ? b.accessGrantId : undefined,
            accessGrantGeneration:
              typeof b.accessGrantGeneration === 'number' ? b.accessGrantGeneration : undefined,
          });
        } catch {
          authorized = false;
        }
      }
    }
    const checkedAt = this.now();
    const report = {
      version: 1,
      operation: 'authorize-binding',
      requestOperation: input.operation,
      binding: b,
      nonce: input.nonce,
      audience: this.audience,
      authorized,
      checkedAt,
      expiresAt: checkedAt + 15000,
    };
    return {
      report,
      attestation: createHmac('sha256', this.key).update(canonicalReport(report)).digest('hex'),
    };
  }
}
