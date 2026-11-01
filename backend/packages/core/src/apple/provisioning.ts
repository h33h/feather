import { SECRET_PURPOSES } from './vault';
import type { Database } from '../shared/database';
import { Failure, hash, id } from '../shared/index';
import type { ExecutorGrant } from '../shared/runner-contracts';
export interface ProvisioningApi {
  create(
    kind: 'certificate' | 'bundle' | 'profile' | 'device',
    request: Record<string, unknown>,
  ): Promise<{
    id: string;
  }>;
  find(
    kind: 'certificate' | 'bundle' | 'profile' | 'device',
    fingerprint: string,
  ): Promise<
    {
      id: string;
    }[]
  >;
}
export class MutationUncertain extends Error {
  constructor() {
    super('MUTATION_UNCERTAIN');
  }
}
export class Provisioning {
  constructor(
    private db: Database,
    private api: ProvisioningApi,
    private now: () => number,
  ) {}
  private async current(grant: ExecutorGrant) {
    const result = await this.db.query(
      "SELECT j.id FROM signing_jobs j JOIN apple_connections c ON c.id=$4 AND c.owner_id=j.owner_id JOIN users u ON u.id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$3 AND j.lease_expires>$6 AND j.state IN('analyzing','provisioning','signing','verifying') AND c.state='ready' AND c.generation=$5 AND u.deleted_at IS NULL",
      [
        grant.jobId,
        grant.ownerId,
        grant.leaseToken,
        grant.connectionId,
        grant.connectionGeneration,
        this.now(),
      ],
    );
    if (!result.rows.length || grant.expiresAt <= this.now())
      throw new Failure('STALE_EXECUTOR_LEASE', 409);
  }
  async ensure(
    grant: ExecutorGrant,
    kind: 'certificate' | 'bundle' | 'profile' | 'device',
    request: Record<string, unknown>,
    keyRef?: string,
  ) {
    await this.current(grant);
    const fingerprint = hash(JSON.stringify(request));
    if (kind === 'certificate') {
      if (!keyRef) throw new Failure('PRIVATE_KEY_NOT_PERSISTED');
      const key = await this.db.query(
        'SELECT id FROM secrets WHERE id=$1 AND owner_id=$2 AND connection_id=$3 AND generation=$4 AND deleted_at IS NULL AND purpose=$5',
        [
          keyRef,
          grant.connectionOwnerId,
          grant.connectionId,
          grant.connectionGeneration,
          SECRET_PURPOSES.distributionKey,
        ],
      );
      if (!key.rows.length) throw new Failure('PRIVATE_KEY_NOT_PERSISTED');
    }
    const operation = await this.db.transaction(async (tx) => {
      await tx.query('SELECT id FROM connections WHERE id=$1 FOR UPDATE', [grant.connectionId]);
      const old = await tx.query<{
        id: string;
        state: string;
        resource_id: string | null;
      }>(
        'SELECT id,state,resource_id FROM provisioning_operations WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND kind=$4 AND fingerprint=$5',
        [
          grant.connectionOwnerId,
          grant.connectionId,
          grant.connectionGeneration,
          kind,
          fingerprint,
        ],
      );
      if (old.rows[0]) return { ...old.rows[0], created: false };
      const operationId = id();
      await tx.query(
        "INSERT INTO provisioning_operations(id,owner_id,connection_id,generation,kind,fingerprint,state,key_ref,created_at) VALUES($1,$2,$3,$4,$5,$6,'submitted',$7,$8)",
        [
          operationId,
          grant.connectionOwnerId,
          grant.connectionId,
          grant.connectionGeneration,
          kind,
          fingerprint,
          keyRef ?? null,
          this.now(),
        ],
      );
      return { id: operationId, state: 'submitted', resource_id: null, created: true };
    });
    if (operation.resource_id) return { id: operation.resource_id, reconciled: true };
    if (!operation.created) {
      const matches = await this.api.find(kind, fingerprint);
      await this.current(grant);
      if (matches.length !== 1)
        throw new Failure(
          matches.length ? 'RESOURCE_RECONCILIATION_AMBIGUOUS' : 'RESOURCE_RECONCILIATION_REQUIRED',
          409,
        );
      await this.db.query(
        "UPDATE provisioning_operations SET state='complete',resource_id=$2 WHERE id=$1",
        [operation.id, matches[0].id],
      );
      return { id: matches[0].id, reconciled: true };
    }
    try {
      await this.current(grant);
      const result = await this.api.create(kind, request);
      await this.current(grant);
      await this.db.query(
        "UPDATE provisioning_operations SET state='complete',resource_id=$2 WHERE id=$1",
        [operation.id, result.id],
      );
      return { ...result, reconciled: false };
    } catch (error) {
      await this.db.query(
        "UPDATE provisioning_operations SET state='unknown' WHERE id=$1 AND state='submitted'",
        [operation.id],
      );
      if (error instanceof Failure) throw error;
      throw new Failure(
        error instanceof MutationUncertain
          ? 'RESOURCE_RECONCILIATION_REQUIRED'
          : 'PROVISIONING_REJECTED',
        409,
      );
    }
  }
}
