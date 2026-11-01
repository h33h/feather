import type { QueryDatabase } from '../shared/database';
import type { BootstrapLease } from '../apple/onboarding';
import type { AppleProvisioningApi } from '../apple/provisioning-client';
import { Failure } from '../shared/errors';
export class BootstrapCertificates {
  constructor(
    private db: QueryDatabase,
    private api: (lease: BootstrapLease) => Promise<AppleProvisioningApi>,
  ) {}
  async find(lease: BootstrapLease, spki: string) {
    return (await this.api(lease)).findCertificates(spki);
  }
  async create(lease: BootstrapLease, csr: string) {
    const row = await this.db.query<{
      identity: {
        spkiSha256: string;
      };
    }>(
      'SELECT identity FROM bootstrap_operations WHERE owner_id=$1 AND connection_id=$2 AND generation=$3 AND nonce=$4',
      [lease.ownerId, lease.connectionId, lease.generation, lease.nonce],
    );
    if (!row.rows[0]?.identity) throw new Failure('BOOTSTRAP_IDENTITY_INVALID');
    const result = await (await this.api(lease)).certificate(csr, row.rows[0].identity.spkiSha256);
    return { id: result.resource.id, certificate: result.certificate };
  }
}
