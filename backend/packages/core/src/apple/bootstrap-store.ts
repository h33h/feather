import type { Database } from '../shared/database';
import type { BootstrapPort, BootstrapLease, BootstrapIdentity } from './onboarding';
import { Failure, token } from '../shared/index';
export type BootstrapCallbacks = {
  prepareIdentity: (lease: BootstrapLease) => Promise<BootstrapIdentity>;
  findCertificates: (
    lease: BootstrapLease,
    spki: string,
  ) => Promise<
    {
      id: string;
      certificate: string;
    }[]
  >;
  createCertificate: (
    lease: BootstrapLease,
    csr: string,
  ) => Promise<{
    id: string;
    certificate: string;
  }>;
};
/** Callback prepares the key only in an authenticated disposable VM and seals it before returning. */
export class DatabaseBootstrapPort implements BootstrapPort {
  constructor(
    private options: BootstrapCallbacks & {
      db: Database;
      now?: () => number;
    },
  ) {}
  private now() {
    return (this.options.now ?? Date.now)();
  }
  async acquire(ownerId: string, connectionId: string, generation: number) {
    const lease = {
      ownerId,
      connectionId,
      generation,
      nonce: token(),
      expiresAt: this.now() + 15 * 60000,
    };
    await this.options.db.transaction(async (tx) => {
      const c = await tx.query(
        "SELECT c.id FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.owner_id=$1 AND c.id=$2 AND c.generation=$3 AND c.state IN('validating','action_required') AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL FOR UPDATE OF c",
        [ownerId, connectionId, generation],
      );
      if (!c.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
      const row = await tx.query(
        "INSERT INTO bootstrap_operations(owner_id,connection_id,generation,nonce,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(owner_id,connection_id,generation) DO UPDATE SET nonce=$4,expires_at=$5 WHERE bootstrap_operations.expires_at<=$6 AND EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$2 AND c.owner_id=$1 AND c.generation=$3 AND c.state IN('validating','action_required') AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL) RETURNING nonce",
        [ownerId, connectionId, generation, lease.nonce, lease.expiresAt, this.now()],
      );
      if (!row.rows.length) throw new Failure('BOOTSTRAP_BUSY', 409);
    });
    return lease;
  }
  async assertCurrent(l: BootstrapLease) {
    const r = await this.options.db.query(
      "SELECT b.nonce FROM bootstrap_operations b JOIN connections c ON c.id=b.connection_id AND c.owner_id=b.owner_id JOIN users u ON u.id=b.owner_id WHERE b.owner_id=$1 AND b.connection_id=$2 AND b.generation=$3 AND b.nonce=$4 AND b.expires_at>$5 AND c.generation=b.generation AND c.state IN('validating','action_required') AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL",
      [l.ownerId, l.connectionId, l.generation, l.nonce, this.now()],
    );
    if (!r.rows.length || l.expiresAt <= this.now())
      throw new Failure('STALE_BOOTSTRAP_LEASE', 409);
  }
  private async update(l: BootstrapLease, sql: string, values: unknown[]) {
    await this.assertCurrent(l);
    const r = await this.options.db.query(sql, [
      l.ownerId,
      l.connectionId,
      l.generation,
      l.nonce,
      this.now(),
      ...values,
    ]);
    if (!r.rows.length) throw new Failure('STALE_BOOTSTRAP_LEASE', 409);
  }
  async prepareIdentity(l: BootstrapLease) {
    await this.assertCurrent(l);
    const r = await this.options.db.query<{
      identity: BootstrapIdentity;
    }>(
      'SELECT identity FROM bootstrap_operations WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND nonce=$4',
      [l.ownerId, l.connectionId, l.generation, l.nonce],
    );
    if (r.rows[0]?.identity) return r.rows[0].identity;
    const identity = await this.options.prepareIdentity(l);
    await this.assertCurrent(l);
    if (
      !identity.secretRef ||
      !/^[a-f0-9]{64}$/.test(identity.spkiSha256) ||
      !identity.csr.startsWith('-----BEGIN CERTIFICATE REQUEST-----\n')
    )
      throw new Failure('BOOTSTRAP_IDENTITY_INVALID');
    const secret = await this.options.db.query(
      "SELECT id FROM secrets WHERE id=$1 AND owner_id=$2 AND connection_id=$3 AND generation=$4 AND purpose='distribution-key' AND deleted_at IS NULL",
      [identity.secretRef, l.ownerId, l.connectionId, l.generation],
    );
    if (!secret.rows.length) throw new Failure('BOOTSTRAP_KEY_NOT_PERSISTED', 409);
    await this.update(
      l,
      "UPDATE bootstrap_operations SET identity=$6 WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND nonce=$4 AND expires_at>$5 AND identity IS NULL AND EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$2 AND c.owner_id=$1 AND c.generation=$3 AND c.state IN('validating','action_required') AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL) RETURNING nonce",
      [JSON.stringify(identity)],
    );
    return identity;
  }
  async claimCertificate(l: BootstrapLease, i: BootstrapIdentity) {
    await this.assertCurrent(l);
    const r = await this.options.db.query(
      "UPDATE bootstrap_operations SET certificate_state='submitted' WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND nonce=$4 AND expires_at>$5 AND identity->>'spkiSha256'=$6 AND certificate_state='prepared' AND EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$2 AND c.owner_id=$1 AND c.generation=$3 AND c.state IN(\'validating\',\'action_required\') AND c.provider=\'asc\' AND u.deleted_at IS NULL AND u.blocked_at IS NULL) RETURNING nonce",
      [l.ownerId, l.connectionId, l.generation, l.nonce, this.now(), i.spkiSha256],
    );
    return r.rows.length ? ('new' as const) : ('reconcile' as const);
  }
  async findCertificates(l: BootstrapLease, s: string) {
    await this.assertCurrent(l);
    const r = await this.options.findCertificates(l, s);
    await this.assertCurrent(l);
    return r;
  }
  async createCertificate(l: BootstrapLease, csr: string) {
    await this.assertCurrent(l);
    const r = await this.options.db.query(
      "UPDATE bootstrap_operations SET certificate_state='unknown' WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND nonce=$4 AND certificate_state='submitted' AND identity->>'csr'=$5 AND EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$2 AND c.owner_id=$1 AND c.generation=$3 AND c.state IN(\'validating\',\'action_required\') AND c.provider=\'asc\' AND u.deleted_at IS NULL AND u.blocked_at IS NULL) RETURNING nonce",
      [l.ownerId, l.connectionId, l.generation, l.nonce, csr],
    );
    if (!r.rows.length) throw new Failure('CERTIFICATE_OPERATION_UNCLAIMED', 409);
    const result = await this.options.createCertificate(l, csr);
    await this.assertCurrent(l);
    return result;
  }
  async markUnknown(l: BootstrapLease, i: BootstrapIdentity) {
    await this.update(
      l,
      "UPDATE bootstrap_operations SET certificate_state='unknown' WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND nonce=$4 AND expires_at>$5 AND identity->>'spkiSha256'=$6 AND EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$2 AND c.owner_id=$1 AND c.generation=$3 AND c.state IN(\'validating\',\'action_required\') AND c.provider=\'asc\' AND u.deleted_at IS NULL AND u.blocked_at IS NULL) RETURNING nonce",
      [i.spkiSha256],
    );
  }
  async commitIdentity(
    l: BootstrapLease,
    i: BootstrapIdentity,
    certificate: {
      id: string;
      pem: string;
      teamId: string;
      expiresAt: number;
    },
  ) {
    await this.update(
      l,
      "UPDATE bootstrap_operations SET certificate_state='committed',certificate=$7 WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND nonce=$4 AND expires_at>$5 AND identity->>'spkiSha256'=$6 AND EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.id=$2 AND c.owner_id=$1 AND c.generation=$3 AND c.state IN(\'validating\',\'action_required\') AND c.provider=\'asc\' AND u.deleted_at IS NULL AND u.blocked_at IS NULL) RETURNING nonce",
      [i.spkiSha256, JSON.stringify(certificate)],
    );
    return true;
  }
}
