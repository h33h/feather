import type { Database } from '../shared/database';
import { Failure, hash, token } from '../shared/index';
import { lockAuthority } from '../apple/access-lifecycle';
type Artifact = {
  id: string;
  job_id: string;
  owner_id: string;
  device_id: string;
  connection_id: string;
  object_key: string;
  metadata: { bundleId: string; version: string; title: string };
  expires_at: number;
  valid_until: number;
};
// Materializing the one authorized artifact bounds join planning on every chunk.
// The signing view fences its authority; the device must have that same binding.
const eligible = `WITH authorized AS MATERIALIZED (SELECT a.* FROM signing_artifacts a WHERE a.id=$1 AND a.owner_id=$2)
 SELECT a.* FROM authorized a JOIN connections c ON c.id=a.connection_id AND c.owner_id=a.connection_owner_id
 JOIN devices d ON d.id=a.device_id AND d.owner_id=a.owner_id AND d.connection_id=a.connection_id AND d.connection_owner_id=a.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM a.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM a.access_grant_generation
 JOIN jobs j ON j.id=a.job_id AND j.owner_id=a.owner_id
 WHERE a.verified AND a.expires_at>$3 AND a.valid_until>$3 AND c.state='ready' AND c.generation=(a.metadata->>'generation')::integer AND d.status='ready' AND d.enrollment_verified_at IS NOT NULL AND d.connection_generation=c.generation AND j.state='ready'`;
const transferable = `${eligible}
 AND EXISTS(SELECT 1 FROM tickets t WHERE t.token_hash=$4 AND t.artifact_id=a.id AND t.owner_id=a.owner_id AND t.state='ready' AND t.expires_at>$3)`;
export class Tickets {
  constructor(
    private db: Database,
    private now: () => number,
    private deviceCheck?: (owner: string, device: string, force: boolean) => Promise<void>,
  ) {}
  async issueDetails(owner: string, artifactId: string) {
    const initial = (await this.db.query<Artifact>(eligible, [artifactId, owner, this.now()]))
      .rows[0];
    if (!initial) throw new Failure('NOT_FOUND', 404);
    await this.deviceCheck?.(owner, initial.device_id, true);
    return this.db.transaction(async (tx) => {
      await lockAuthority(tx);
      const artifact = (await tx.query<Artifact>(eligible, [artifactId, owner, this.now()]))
        .rows[0];
      if (!artifact) throw new Failure('NOT_FOUND', 404);
      const cap = token(),
        expiresAt = Math.min(Number(artifact.expires_at), Number(artifact.valid_until));
      await tx.query(
        "INSERT INTO tickets(token_hash,owner_id,artifact_id,state,expires_at) VALUES($1,$2,$3,'ready',$4)",
        [hash(cap), owner, artifactId, expiresAt],
      );
      return { ticket: cap, expiresAt };
    });
  }
  async issue(owner: string, artifactId: string) {
    return (await this.issueDetails(owner, artifactId)).ticket;
  }
  async resolve(cap: string) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(cap)) throw new Failure('NOT_FOUND', 404);
    const link = (
      await this.db.query<{ owner_id: string; artifact_id: string }>(
        "SELECT owner_id,artifact_id FROM tickets WHERE token_hash=$1 AND state='ready' AND expires_at>$2",
        [hash(cap), this.now()],
      )
    ).rows[0];
    if (!link) throw new Failure('NOT_FOUND', 404);
    let artifact = (
      await this.db.query<Artifact>(eligible, [link.artifact_id, link.owner_id, this.now()])
    ).rows[0];
    if (!artifact) throw new Failure('NOT_FOUND', 404);
    await this.deviceCheck?.(artifact.owner_id, artifact.device_id, false);
    artifact = (
      await this.db.query<Artifact>(eligible, [link.artifact_id, link.owner_id, this.now()])
    ).rows[0];
    const current = await this.db.query(
      "SELECT token_hash FROM tickets WHERE token_hash=$1 AND state='ready' AND expires_at>$2",
      [hash(cap), this.now()],
    );
    if (!artifact || !current.rows.length) throw new Failure('NOT_FOUND', 404);
    return artifact;
  }
  async beginTransfer(cap: string) {
    const artifact = await this.resolve(cap);
    const capHash = hash(cap);
    // These are immutable locators only. Every check reloads current authority.
    const load = async () => {
      const current = (
        await this.db.query<Artifact>(transferable, [
          artifact.id,
          artifact.owner_id,
          this.now(),
          capHash,
        ])
      ).rows[0];
      if (!current) throw new Failure('NOT_FOUND', 404);
      return current;
    };
    return {
      artifact,
      check: async () => {
        const current = await load();
        await this.deviceCheck?.(current.owner_id, current.device_id, false);
        return load();
      },
    };
  }
}
