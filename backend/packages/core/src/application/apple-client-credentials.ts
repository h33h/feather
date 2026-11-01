import { createPrivateKey, type KeyObject } from 'node:crypto';
import type { QueryDatabase } from '../shared/database';
import type { Vault } from '../apple/vault';
import { assertAppleAccess } from '../apple/access';
import { Failure } from '../shared/errors';
import { AppleProvisioningApi } from '../apple/provisioning-client';
import type { AppleRequestPort } from '../apple/request-port';
import type { BootstrapLease, parseTeamKey } from '../apple/onboarding';
import type { ExecutorGrant } from '../shared/runner-contracts';
import type { AppleAccess } from '../apple/access';
export type AppleClientFactory = (
  key: { issuerId: string; keyId: string; privateKey: KeyObject },
  guard: () => Promise<void>,
) => AppleRequestPort;
/** Each factory binds credentials to a scenario and rechecks authority for every Apple request. */
export class AppleClientCredentials {
  constructor(
    private db: QueryDatabase,
    private vault: Pick<Vault, 'openForBootstrap' | 'openForJob' | 'openForConnection'>,
    private client: AppleClientFactory,
    private now: () => number,
  ) {}
  async bootstrap(lease: BootstrapLease) {
    const guard = async () => {
      const current = await this.db.query(
        "SELECT c.id FROM bootstrap_operations b JOIN connections c ON c.id=b.connection_id AND c.owner_id=b.owner_id JOIN users u ON u.id=b.owner_id WHERE b.owner_id=$1 AND b.connection_id=$2 AND b.generation=$3 AND b.nonce=$4 AND b.expires_at=$5 AND b.expires_at>$6 AND c.generation=b.generation AND c.state IN('validating','action_required') AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL",
        [
          lease.ownerId,
          lease.connectionId,
          lease.generation,
          lease.nonce,
          lease.expiresAt,
          this.now(),
        ],
      );
      if (!current.rows.length) throw new Failure('STALE_BOOTSTRAP_LEASE', 409);
    };
    await guard();
    const r = await this.db.query<{
      issuer_id: string;
      key_id: string;
      secret_ref: string;
    }>(
      'SELECT issuer_id,key_id,secret_ref FROM connections WHERE id=$1 AND owner_id=$2 AND generation=$3',
      [lease.connectionId, lease.ownerId, lease.generation],
    );
    if (!r.rows[0]?.secret_ref) throw new Failure('SECRET_UNAVAILABLE', 404);
    const p8 = await this.vault.openForBootstrap(lease, r.rows[0].secret_ref, 'p8');
    try {
      return new AppleProvisioningApi(
        this.client(
          {
            issuerId: r.rows[0].issuer_id,
            keyId: r.rows[0].key_id,
            privateKey: createPrivateKey(p8),
          },
          guard,
        ),
        this.now,
      );
    } finally {
      p8.fill(0);
    }
  }
  async job(grant: ExecutorGrant) {
    const guard = async () => {
      await assertAppleAccess(this.db, { ...grant, generation: grant.connectionGeneration });
      const r = await this.db.query(
        "SELECT j.id FROM signing_jobs j JOIN apple_connections c ON c.id=j.connection_id AND c.owner_id=j.owner_id JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id JOIN users u ON u.id=j.owner_id JOIN executor_tasks t ON t.job_id=j.id AND t.owner_id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$3 AND j.lease_expires>$4 AND j.state IN('analyzing','provisioning','signing','verifying') AND c.id=$5 AND c.generation=$6 AND j.connection_generation=c.generation AND d.id=$7 AND d.status='ready' AND d.connection_generation=c.generation AND c.state='ready' AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL AND t.nonce=$8 AND t.consumed=false AND t.expires_at>$4 AND t.binding->>'isolationInstanceId'=$9",
        [
          grant.jobId,
          grant.ownerId,
          grant.leaseToken,
          this.now(),
          grant.connectionId,
          grant.connectionGeneration,
          grant.deviceId,
          grant.taskNonce,
          grant.isolationInstanceId,
        ],
      );
      if (!r.rows.length || grant.expiresAt <= this.now())
        throw new Failure('STALE_EXECUTOR_LEASE', 409);
    };
    await guard();
    const row = await this.db.query<{
      issuer_id: string;
      key_id: string;
      secret_ref: string;
    }>(
      'SELECT issuer_id,key_id,secret_ref FROM connections WHERE id=$1 AND owner_id=$2 AND generation=$3',
      [grant.connectionId, grant.connectionOwnerId, grant.connectionGeneration],
    );
    if (!row.rows[0]?.secret_ref) throw new Failure('SECRET_UNAVAILABLE', 404);
    const p8 = await this.vault.openForJob(
      grant.ownerId,
      row.rows[0].secret_ref,
      grant.jobId,
      grant.leaseToken,
    );
    try {
      return new AppleProvisioningApi(
        this.client(
          {
            issuerId: row.rows[0].issuer_id,
            keyId: row.rows[0].key_id,
            privateKey: createPrivateKey(p8),
          },
          guard,
        ),
        this.now,
      );
    } finally {
      p8.fill(0);
    }
  }
  async ready(
    binding: AppleAccess,
    probe?: (
      resourceId: string,
      udid: string,
    ) => Promise<{
      eligible?: boolean;
      processing?: boolean;
      ineligible?: boolean;
    }>,
  ) {
    const row = await this.db.query<{
      issuer_id: string;
      key_id: string;
    }>(
      'SELECT issuer_id,key_id FROM apple_connections WHERE id=$1 AND owner_id=$2 AND generation=$3',
      [binding.connectionId, binding.ownerId, binding.generation],
    );
    if (!row.rows[0]) throw new Failure('CONNECTION_CHANGED', 409);
    const access = await assertAppleAccess(this.db, binding);
    const p8 = await this.vault.openForConnection(
      access.connectionOwnerId,
      binding.connectionId,
      binding.generation,
    );
    try {
      return new AppleProvisioningApi(
        this.client(
          {
            issuerId: row.rows[0].issuer_id,
            keyId: row.rows[0].key_id,
            privateKey: createPrivateKey(p8),
          },
          async () => {
            await assertAppleAccess(this.db, binding);
            const r = await this.db.query(
              "SELECT id FROM apple_connections WHERE id=$1 AND owner_id=$2 AND generation=$3 AND state='ready'",
              [binding.connectionId, binding.ownerId, binding.generation],
            );
            if (!r.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
          },
        ),
        this.now,
        probe,
      );
    } finally {
      p8.fill(0);
    }
  }
  async validateTeam(
    key: ReturnType<typeof parseTeamKey>,
    binding: { ownerId: string; connectionId: string; generation: number },
  ) {
    return new AppleProvisioningApi(
      this.client({ issuerId: key.issuerId, keyId: key.keyId, privateKey: key.key }, async () => {
        const r = await this.db.query(
          "SELECT c.id FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$1 AND c.owner_id=$2 AND c.generation=$3 AND c.state='validating' AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL",
          [binding.connectionId, binding.ownerId, binding.generation],
        );
        if (!r.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
      }),
      this.now,
    ).validateTeam();
  }
}
