import { lockAuthority } from './access-lifecycle';
import { X509Certificate, createHash } from 'node:crypto';
import type { Database } from '../shared/database';
import { Failure, id, token } from '../shared/index';
/** Authenticated automatic signing setup invokes this; this only changes owned service rows, never Apple resources. */
export class BootstrapRenewal {
  constructor(
    private db: Database,
    private now: () => number,
  ) {}
  async prepare(owner: string, connection: string) {
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      const user = await tx.query(
        'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',
        [owner],
      );
      if (!user.rows.length) throw new Failure('USER_UNAVAILABLE', 404);
      const row = await tx.query<{
        generation: number;
        team_id: string;
        secret_ref: string | null;
        identity: {
          secretRef: string;
          spkiSha256: string;
        };
        certificate: {
          pem: string;
        };
      }>(
        "SELECT c.generation,c.team_id,c.secret_ref,b.identity,b.certificate FROM connections c JOIN bootstrap_operations b ON b.connection_id=c.id AND b.owner_id=c.owner_id AND b.generation=c.generation WHERE c.id=$1 AND c.owner_id=$2 AND c.provider='asc' AND c.state IN('ready','action_required') AND b.certificate_state='committed' FOR UPDATE OF c,b",
        [connection, owner],
      );
      const current = row.rows[0];
      if (!current?.identity?.secretRef || !current.certificate?.pem || !current.secret_ref)
        throw new Failure('OWNED_CERTIFICATE_REQUIRED', 409);
      let certificate: X509Certificate;
      try {
        certificate = new X509Certificate(current.certificate.pem);
      } catch {
        throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
      }
      const digest = createHash('sha256')
        .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
        .digest('hex');
      if (
        digest !== current.identity.spkiSha256 ||
        /^OU=([A-Z0-9]{10})$/m.exec(certificate.subject)?.[1] !== current.team_id
      )
        throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
      if (Date.parse(certificate.validTo) > this.now())
        throw new Failure('CERTIFICATE_NOT_EXPIRED', 409);
      const active = await tx.query(
        "SELECT id FROM jobs WHERE owner_id=$1 AND state IN('analyzing','provisioning','signing','verifying')",
        [owner],
      );
      if (active.rows.length) throw new Failure('ACTIVE_JOB_EXISTS', 409);
      const credential = await tx.query(
        "SELECT id FROM secrets WHERE id=$1 AND owner_id=$2 AND connection_id=$3 AND generation=$4 AND purpose='p8' AND deleted_at IS NULL",
        [current.secret_ref, owner, connection, current.generation],
      );
      if (!credential.rows.length) throw new Failure('APPLE_CREDENTIAL_REQUIRED', 409);
      const secret = await tx.query(
        "UPDATE secrets SET deleted_at=$5 WHERE id=$1 AND owner_id=$2 AND connection_id=$3 AND generation=$4 AND purpose='distribution-key' AND deleted_at IS NULL RETURNING id",
        [current.identity.secretRef, owner, connection, current.generation, this.now()],
      );
      if (!secret.rows.length) throw new Failure('OWNED_CERTIFICATE_REQUIRED', 409);
      await tx.query(
        'INSERT INTO secret_deletions(id,owner_id,secret_id,created_at) VALUES($1,$2,$3,$4) ON CONFLICT(owner_id,secret_id) DO NOTHING',
        [id(), owner, current.identity.secretRef, this.now()],
      );
      await tx.query(
        'UPDATE identities SET expires_at=LEAST(expires_at,$3) WHERE owner_id=$1 AND connection_id=$2',
        [owner, connection, this.now()],
      );
      await tx.query(
        'UPDATE profiles SET expires_at=LEAST(expires_at,$3) WHERE owner_id=$1 AND connection_id=$2',
        [owner, connection, this.now()],
      );
      await tx.query(
        'UPDATE artifacts SET expires_at=LEAST(expires_at,$3),valid_until=LEAST(valid_until,$3) WHERE owner_id=$1 AND connection_id=$2',
        [owner, connection, this.now()],
      );
      await tx.query(
        "UPDATE tickets SET state='revoked' WHERE owner_id=$1 AND artifact_id IN(SELECT id FROM artifacts WHERE owner_id=$1 AND connection_id=$2)",
        [owner, connection],
      );
      await tx.query(
        "UPDATE devices SET status='apple_processing' WHERE owner_id=$1 AND connection_id=$2 AND connection_generation=$3 AND status IN('ready','registering','apple_processing')",
        [owner, connection, current.generation],
      );
      await tx.query(
        "UPDATE bootstrap_operations SET identity=NULL,certificate=NULL,certificate_state='prepared',nonce=$4,expires_at=0 WHERE owner_id=$1 AND connection_id=$2 AND generation=$3",
        [owner, connection, current.generation, token()],
      );
      await tx.query(
        "UPDATE connections SET state='action_required',last_error='CERTIFICATE_REQUIRED' WHERE id=$1 AND owner_id=$2 AND generation=$3",
        [connection, owner, current.generation],
      );
      await tx.query(
        "INSERT INTO audit(id,owner_id,event,metadata,created_at) VALUES($1,$2,'certificate_renewal_requested',$3,$4)",
        [
          id(),
          owner,
          JSON.stringify({ connectionId: connection, generation: current.generation }),
          this.now(),
        ],
      );
      return {
        connectionId: connection,
        generation: current.generation,
        state: 'action_required',
        reason: 'CERTIFICATE_REQUIRED',
      };
    });
  }
}
