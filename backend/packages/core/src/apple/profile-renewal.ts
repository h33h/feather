import type { Database } from '../shared/database';
import type { ControlResource } from '../devices/eligibility';
import type { AppleAccess } from './access';
import type { ExecutorGrant } from '../shared/runner-contracts';
import { canonicalReport } from '../shared/canonical-json';
import { Failure, hash, id } from '../shared/index';
type Binding = AppleAccess | ExecutorGrant;
/** A new revision is chosen only after Apple reports the previously owned exact profile expired. */
export class ProfileRenewal {
  constructor(
    private o: {
      db: Database;
      now?: () => number;
    },
  ) {}
  private now() {
    return (this.o.now ?? Date.now)();
  }
  async chooseName(
    binding: Binding,
    baseName: string,
    bundleResourceId: string,
    findProfiles: (bundleResourceId: string, name: string) => Promise<ControlResource[]>,
    current: () => Promise<unknown>,
  ) {
    const generation =
      'connectionGeneration' in binding ? binding.connectionGeneration : binding.generation;
    const fingerprint = hash(canonicalReport({ baseName, bundleResourceId }));
    for (let attempt = 0; attempt < 5; attempt++) {
      await current();
      const old = await this.o.db.query<{
        resource_id: string;
      }>(
        "SELECT resource_id FROM provisioning_operations WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND kind='profile-renewal' AND fingerprint=$4",
        [binding.connectionOwnerId, binding.connectionId, generation, fingerprint],
      );
      const revision = Number(old.rows[0]?.resource_id ?? '0');
      if (!Number.isSafeInteger(revision) || revision < 0 || revision > 1000)
        throw new Failure('PROFILE_RENEWAL_STATE_INVALID', 409);
      const name = revision ? baseName + '-r' + revision : baseName;
      const rows = await findProfiles(bundleResourceId, name);
      await current();
      if (rows.length > 1) throw new Failure('RESOURCE_RECONCILIATION_AMBIGUOUS', 409);
      if (!rows.length) return name;
      const row = rows[0];
      if (row.attributes.name !== name) throw new Failure('PROFILE_RESOURCE_MISMATCH', 403);
      const expiration =
        typeof row.attributes.expirationDate === 'string'
          ? Date.parse(row.attributes.expirationDate)
          : NaN;
      if (!Number.isFinite(expiration)) throw new Failure('PROFILE_EXPIRY_UNKNOWN', 409);
      if (expiration > this.now()) return name;
      const advanced = await this.o.db.transaction(async (tx) => {
        await tx.query('SELECT pg_advisory_xact_lock(736490)');
        await tx.query('SELECT id FROM connections WHERE id=$1 FOR UPDATE', [binding.connectionId]);
        const c = await tx.query(
          "SELECT c.id FROM apple_connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$1 AND c.owner_id=$2 AND c.generation=$3 AND c.state='ready' AND c.provider='asc' AND u.deleted_at IS NULL FOR UPDATE OF u",
          [binding.connectionId, binding.ownerId, generation],
        );
        if (!c.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
        if ('jobId' in binding) {
          const job = await tx.query(
            "SELECT j.id FROM signing_jobs j JOIN signing_devices d ON d.id=j.device_id AND d.owner_id=j.owner_id WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$3 AND j.lease_expires>$4 AND j.connection_id=$5 AND j.connection_generation=$6 AND j.state IN('analyzing','provisioning','signing','verifying') AND d.id=$7 AND d.status='ready' AND d.connection_generation=$6",
            [
              binding.jobId,
              binding.ownerId,
              binding.leaseToken,
              this.now(),
              binding.connectionId,
              generation,
              binding.deviceId,
            ],
          );
          if (!job.rows.length) throw new Failure('STALE_EXECUTOR_LEASE', 409);
        }
        const r = await tx.query<{
          resource_id: string;
        }>(
          "SELECT resource_id FROM provisioning_operations WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND kind='profile-renewal' AND fingerprint=$4 FOR UPDATE",
          [binding.connectionOwnerId, binding.connectionId, generation, fingerprint],
        );
        if (Number(r.rows[0]?.resource_id ?? '0') !== revision) return false;
        if (r.rows.length)
          await tx.query(
            "UPDATE provisioning_operations SET resource_id=$5 WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND kind='profile-renewal' AND fingerprint=$4",
            [
              binding.connectionOwnerId,
              binding.connectionId,
              generation,
              fingerprint,
              String(revision + 1),
            ],
          );
        else
          await tx.query(
            "INSERT INTO provisioning_operations(id,owner_id,connection_id,generation,kind,fingerprint,state,resource_id,created_at) VALUES($1,$2,$3,$4,'profile-renewal',$5,'selected',$6,$7)",
            [
              id(),
              binding.connectionOwnerId,
              binding.connectionId,
              generation,
              fingerprint,
              String(revision + 1),
              this.now(),
            ],
          );
        return true;
      });
      if (advanced) await current();
    }
    throw new Failure('PROFILE_RENEWAL_BUSY', 409);
  }
}
