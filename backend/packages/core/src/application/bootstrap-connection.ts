import type { Database } from '../shared/database';
import type { OnboardingPort } from '../apple/onboarding';
import type { BootstrapRenewal } from '../apple/bootstrap-renewal';
import { Failure } from '../shared/errors';
export class BootstrapConnection {
  constructor(
    private db: Database,
    private renewal: Pick<BootstrapRenewal, 'prepare'>,
    private proof: {
      prove(owner: string, connection: string, generation: number): Promise<{ teamId: string }>;
    },
    private onboarding: Pick<OnboardingPort, 'commit'>,
    private now: () => number,
  ) {}
  async run(owner: string) {
    const expired = await this.db.query<{
      id: string;
    }>(
      "SELECT c.id FROM connections c JOIN bootstrap_operations b ON b.connection_id=c.id AND b.owner_id=c.owner_id AND b.generation=c.generation WHERE c.owner_id=$1 AND c.state='ready' AND c.provider='asc' AND b.certificate_state='committed' AND (b.certificate->>'expiresAt')::bigint<=$2",
      [owner, this.now()],
    );
    if (expired.rows[0]) await this.renewal.prepare(owner, expired.rows[0].id);
    await this.db.transaction(async (tx) => {
      const rows = await tx.query<{
        id: string;
        generation: number;
        state: string;
      }>(
        "SELECT c.id,c.generation,c.state FROM connections c JOIN users u ON u.id=c.owner_id WHERE c.owner_id=$1 AND c.provider='asc' AND u.deleted_at IS NULL AND u.blocked_at IS NULL FOR UPDATE OF c,u",
        [owner],
      );
      const c = rows.rows[0];
      if (!c) throw new Failure('CONNECTION_UNAVAILABLE', 409);
      if (c.state === 'ready') {
        const own = await tx.query(
          "SELECT b.connection_id FROM bootstrap_operations b JOIN secrets s ON s.id=b.identity->>'secretRef' AND s.owner_id=b.owner_id AND s.connection_id=b.connection_id WHERE b.owner_id=$1 AND b.connection_id=$2 AND b.generation=$3 AND b.certificate_state='committed' AND s.deleted_at IS NULL AND s.generation=$3",
          [owner, c.id, c.generation],
        );
        if (own.rows.length) throw new Failure('BOOTSTRAP_NOT_REQUIRED', 409);
        const active = await tx.query(
          "SELECT id FROM jobs WHERE owner_id=$1 AND state IN('queued','analyzing','provisioning','signing','verifying')",
          [owner],
        );
        if (active.rows.length) throw new Failure('ACTIVE_JOB_EXISTS', 409);
        await tx.query(
          "UPDATE connections SET state='action_required',last_error='CERTIFICATE_REQUIRED' WHERE id=$1 AND owner_id=$2 AND generation=$3 AND state='ready'",
          [c.id, owner, c.generation],
        );
      }
    });
    const row = await this.db.query<{
      id: string;
      generation: number;
      issuer_id: string;
      key_id: string;
      secret_ref: string;
    }>(
      "SELECT id,generation,issuer_id,key_id,secret_ref FROM connections WHERE owner_id=$1 AND provider='asc' AND state='action_required' AND last_error IN('TEAM_PROOF_REQUIRED','CERTIFICATE_REQUIRED')",
      [owner],
    );
    const c = row.rows[0];
    if (!c) throw new Failure('BOOTSTRAP_NOT_REQUIRED', 409);
    const proof = await this.proof.prove(owner, c.id, c.generation);
    if (
      !(await this.onboarding.commit(owner, c.id, c.generation, {
        issuerId: c.issuer_id,
        keyId: c.key_id,
        secretRef: c.secret_ref,
        teamId: proof.teamId,
      }))
    )
      throw new Failure('CONNECTION_CHANGED', 409);
    return { state: 'ready', teamId: proof.teamId };
  }
}
