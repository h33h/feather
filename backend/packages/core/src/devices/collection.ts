import { createHash } from 'node:crypto';
import { assertAppleAccess, lockPrincipalConnections, type AppleAccess } from '../apple/access';
import type { Database, QueryDatabase } from '../shared/database';
import { normalizeUdid, type CmsVerifier, type DeviceOnboarding } from './onboarding';
import { Failure, hash, id, token } from '../shared/index';
export type CollectedDeviceStatus =
  | 'collected'
  | 'not_registered'
  | 'registering'
  | 'apple_processing'
  | 'certificate_required'
  | 'ready'
  | 'ineligible'
  | 'disabled'
  | 'connection_unavailable';
export type CollectedDeviceBinding = {
  deviceId: string;
  connectionId: string;
  teamId: string;
  generation: number;
  status: string;
  shared: boolean;
};
export type CollectedDevice = {
  id: string;
  name: string;
  udid: string;
  product: string | null;
  osVersion: string | null;
  createdAt: number;
  verifiedAt: number;
  status: CollectedDeviceStatus;
  bindings: CollectedDeviceBinding[];
};
type CollectionRow = {
  id: string;
  owner_id: string;
  name: string;
  udid: string;
  udid_hash: string;
  product: string | null;
  os_version: string | null;
  enrollment_verified_at: number;
  enrollment_cms_sha256: string;
  created_at: number;
};
type CheckRow = {
  id: string;
  collected_device_id: string;
  owner_id: string;
  connection_id: string;
  connection_owner_id: string;
  generation: number;
  access_grant_id: string | null;
  access_grant_generation: number | null;
  device_id: string | null;
  status: string;
  failures: number;
  lease_token: string;
};
const mask = (udid: string) => '••••' + udid.slice(-4);
const currentCheck = `EXISTS(SELECT 1 FROM apple_connections c WHERE c.id=k.connection_id AND c.owner_id=k.owner_id AND c.connection_owner_id=k.connection_owner_id AND c.generation=k.generation AND c.access_grant_id IS NOT DISTINCT FROM k.access_grant_id AND c.access_grant_generation IS NOT DISTINCT FROM k.access_grant_generation AND c.state='ready' AND c.provider='asc')`;
export type NativeCollectionSession = (
  tx: QueryDatabase,
  owner: string,
  sessionId: string,
  now: number,
) => Promise<boolean>;
/** Collecting identity never grants Apple access. Every reconciliation checks the current principal binding. */
export class DeviceCollection {
  constructor(
    private db: Database,
    private onboarding: DeviceOnboarding,
    private now: () => number,
    private verify: CmsVerifier,
    private nativeSession: NativeCollectionSession,
  ) {}
  private async owner(db: QueryDatabase, owner: string) {
    if (
      !(
        await db.query(
          'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
          [owner],
        )
      ).rows.length
    )
      throw new Failure('OWNER_NOT_FOUND', 404);
  }
  async challenge(owner: string, sessionToken: string) {
    return this.createChallenge(owner, hash(sessionToken));
  }
  async challengeNative(owner: string, sessionId: string) {
    return this.createChallenge(owner, 'native:' + sessionId);
  }
  private async liveSession(tx: QueryDatabase, owner: string, binding: string) {
    if (binding.startsWith('native:'))
      return this.nativeSession(tx, owner, binding.slice(7), this.now());
    return !!(
      await tx.query(
        'SELECT token_hash FROM sessions WHERE owner_id=$1 AND token_hash=$2 AND expires_at>$3 FOR UPDATE',
        [owner, binding, this.now()],
      )
    ).rows.length;
  }
  private async createChallenge(owner: string, binding: string) {
    const raw = token(),
      expiresAt = this.now() + 600000;
    await this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, owner);
      if (
        !(
          await tx.query(
            'SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL AND blocked_at IS NULL FOR UPDATE',
            [owner],
          )
        ).rows.length
      )
        throw new Failure('SESSION_REQUIRED', 401);
      if (!(await this.liveSession(tx, owner, binding))) throw new Failure('SESSION_REQUIRED', 401);
      const pending = await tx.query<{ count: number }>(
        'SELECT COUNT(*)::int AS count FROM device_collection_challenges WHERE owner_id=$1 AND consumed_at IS NULL AND expires_at>$2',
        [owner, this.now()],
      );
      if (pending.rows[0].count >= 10) throw new Failure('DEVICE_CHALLENGE_LIMIT', 429);
      await tx.query(
        'INSERT INTO device_collection_challenges(id,owner_id,token_hash,session_hash,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6)',
        [id(), owner, hash(raw), binding, expiresAt, this.now()],
      );
    });
    return { challenge: raw, expiresAt };
  }
  async callback(raw: string, body: Buffer) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(raw) || !body.length || body.length > 65536)
      throw new Failure('INVALID_DEVICE_CALLBACK');
    const payload = await this.verify(body);
    if (
      payload.signatureVerified !== true ||
      payload.issuerTrusted !== true ||
      payload.deviceCertificate !== true ||
      payload.challenge !== raw ||
      (payload.product !== undefined &&
        !/^(?:iPhone|iPad)\d{1,3},\d{1,3}$/.test(payload.product)) ||
      (payload.version !== undefined && !/^\d+(?:\.\d+){0,2}$/.test(payload.version))
    )
      throw new Failure('INVALID_DEVICE_CALLBACK');
    const udid = normalizeUdid(payload.udid);
    const result = await this.db.transaction(async (tx) => {
      const initial = (
        await tx.query<{
          owner_id: string;
        }>('SELECT owner_id FROM device_collection_challenges WHERE token_hash=$1', [hash(raw)])
      ).rows[0];
      if (!initial) throw new Failure('CHALLENGE_EXPIRED_OR_USED', 410);
      await lockPrincipalConnections(tx, initial.owner_id);
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [initial.owner_id]);
      const active = await tx.query<{ owner_id: string; session_hash: string }>(
        `SELECT d.owner_id,d.session_hash FROM device_collection_challenges d JOIN users u ON u.id=d.owner_id
        WHERE d.token_hash=$1 AND d.consumed_at IS NULL AND d.expires_at>$2 AND u.deleted_at IS NULL AND u.blocked_at IS NULL FOR UPDATE OF d`,
        [hash(raw), this.now()],
      );
      if (
        !active.rows.length ||
        !(await this.liveSession(tx, active.rows[0].owner_id, active.rows[0].session_hash))
      )
        throw new Failure('CHALLENGE_EXPIRED_OR_USED', 410);
      await tx.query('UPDATE device_collection_challenges SET consumed_at=$2 WHERE token_hash=$1', [
        hash(raw),
        this.now(),
      ]);
      const stored = await tx.query<{
        id: string;
      }>(
        `INSERT INTO collected_devices(id,owner_id,name,udid,udid_hash,product,os_version,enrollment_verified_at,enrollment_cms_sha256,created_at,updated_at)
    VALUES($1,$2,$9,$3,$4,$5,$6,$7,$8,$7,$7) ON CONFLICT(owner_id,udid_hash) DO UPDATE SET
     product=COALESCE(EXCLUDED.product,collected_devices.product),
     os_version=COALESCE(EXCLUDED.os_version,collected_devices.os_version),
     enrollment_verified_at=$7,enrollment_cms_sha256=$8,updated_at=$7 RETURNING id`,
        [
          id(),
          initial.owner_id,
          udid,
          hash(udid),
          payload.product ?? null,
          payload.version ?? null,
          this.now(),
          createHash('sha256').update(body).digest('hex'),
          payload.product?.startsWith('iPad') ? 'iPad' : 'iPhone',
        ],
      );
      // Only a new, verified owner/session challenge can undo an explicit local removal.
      const restored = await tx.query<{
        id: string;
      }>(
        `UPDATE devices SET status='collected',selected=false,apple_resource_id=NULL,enrollment_verified_at=$3,enrollment_cms_sha256=$4,os_version=COALESCE($5,os_version)
    WHERE owner_id=$1 AND udid_hash=$2 AND status='locally_removed' RETURNING id`,
        [
          initial.owner_id,
          hash(udid),
          this.now(),
          createHash('sha256').update(body).digest('hex'),
          payload.version ?? null,
        ],
      );
      await tx.query(
        `UPDATE device_collection_checks SET status=CASE WHEN device_id=ANY($2::text[]) THEN 'collected' ELSE status END,next_check_at=0,lease_token=NULL,lease_until=0,failures=0,last_error=NULL WHERE collected_device_id=$1`,
        [stored.rows[0].id, restored.rows.map((device) => device.id)],
      );
      return stored.rows[0];
    });
    return { ...result, status: 'collected', udid: mask(udid) };
  }
  async redeemProfile(raw: string) {
    if (!/^[A-Za-z0-9_-]{43}$/.test(raw)) throw new Failure('PROFILE_LINK_EXPIRED_OR_USED', 410);
    return this.db.transaction(async (tx) => {
      const candidate = (
        await tx.query<{ owner_id: string }>(
          'SELECT owner_id FROM device_collection_challenges WHERE token_hash=$1',
          [hash(raw)],
        )
      ).rows[0];
      if (!candidate) throw new Failure('PROFILE_LINK_EXPIRED_OR_USED', 410);
      await lockPrincipalConnections(tx, candidate.owner_id);
      await tx.query('SELECT id FROM users WHERE id=$1 FOR UPDATE', [candidate.owner_id]);
      const active = (
        await tx.query<{ owner_id: string; session_hash: string; expires_at: number }>(
          `SELECT d.owner_id,d.session_hash,d.expires_at FROM device_collection_challenges d JOIN users u ON u.id=d.owner_id WHERE d.token_hash=$1 AND d.profile_downloaded_at IS NULL AND d.consumed_at IS NULL AND d.expires_at>$2 AND u.deleted_at IS NULL AND u.blocked_at IS NULL FOR UPDATE OF d`,
          [hash(raw), this.now()],
        )
      ).rows[0];
      if (!active || !(await this.liveSession(tx, active.owner_id, active.session_hash)))
        throw new Failure('PROFILE_LINK_EXPIRED_OR_USED', 410);
      await tx.query(
        'UPDATE device_collection_challenges SET profile_downloaded_at=$2 WHERE token_hash=$1',
        [hash(raw), this.now()],
      );
      return { challenge: raw, expiresAt: Number(active.expires_at) };
    });
  }
  private async seed(owner: string) {
    await this.db.transaction(async (tx) => {
      // Match deleteAccount's real-connections then principal lock order.
      await lockPrincipalConnections(tx, owner);
      await this.owner(tx, owner);
      await tx.query(
        `INSERT INTO device_collection_checks(id,collected_device_id,owner_id,connection_id,connection_owner_id,generation,access_grant_id,access_grant_generation,device_id,status)
   SELECT gen_random_uuid()::text,d.id,d.owner_id,c.id,c.connection_owner_id,c.generation,c.access_grant_id,c.access_grant_generation,existing.id,
    CASE WHEN existing.connection_generation=c.generation AND existing.connection_owner_id=c.connection_owner_id AND existing.access_grant_id IS NOT DISTINCT FROM c.access_grant_id AND existing.access_grant_generation IS NOT DISTINCT FROM c.access_grant_generation THEN existing.status ELSE 'collected' END
   FROM collected_devices d JOIN apple_connections c ON c.owner_id=d.owner_id LEFT JOIN devices existing ON existing.owner_id=d.owner_id AND existing.connection_id=c.id AND existing.udid_hash=d.udid_hash
   WHERE d.owner_id=$1 AND c.state='ready' AND c.provider='asc'
   ON CONFLICT(collected_device_id,connection_id) DO UPDATE SET connection_owner_id=EXCLUDED.connection_owner_id,generation=EXCLUDED.generation,access_grant_id=EXCLUDED.access_grant_id,access_grant_generation=EXCLUDED.access_grant_generation,
    status='collected',next_check_at=0,failures=0,last_error=NULL,lease_token=NULL,lease_until=0
   WHERE device_collection_checks.generation<>EXCLUDED.generation OR device_collection_checks.connection_owner_id<>EXCLUDED.connection_owner_id OR device_collection_checks.access_grant_id IS DISTINCT FROM EXCLUDED.access_grant_id OR device_collection_checks.access_grant_generation IS DISTINCT FROM EXCLUDED.access_grant_generation`,
        [owner],
      );
    });
  }
  async list(owner: string): Promise<CollectedDevice[]> {
    const devices = await this.db.query<CollectionRow>(
      'SELECT d.* FROM collected_devices d JOIN users u ON u.id=d.owner_id WHERE d.owner_id=$1 AND u.deleted_at IS NULL ORDER BY d.created_at DESC,d.id',
      [owner],
    );
    const bindings = await this.db.query<{
      collected_device_id: string;
      device_id: string | null;
      connection_id: string;
      team_id: string;
      generation: number;
      status: string;
      shared: boolean;
    }>(
      `SELECT k.collected_device_id,k.device_id,k.connection_id,c.team_id,k.generation,
   CASE WHEN d.status='locally_removed' THEN 'locally_removed' WHEN d.connection_generation=k.generation AND d.connection_owner_id=k.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM k.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM k.access_grant_generation AND d.status!='collected' THEN d.status ELSE k.status END AS status,c.connection_owner_id<>c.owner_id AS shared
   FROM device_collection_checks k JOIN apple_connections c ON c.id=k.connection_id AND c.owner_id=k.owner_id LEFT JOIN devices d ON d.id=k.device_id AND d.owner_id=k.owner_id WHERE k.owner_id=$1 AND ${currentCheck} ORDER BY c.connection_owner_id<>c.owner_id,c.id`,
      [owner],
    );
    const prior = await this.db.query<{
      collected_device_id: string;
    }>('SELECT DISTINCT collected_device_id FROM device_collection_checks WHERE owner_id=$1', [
      owner,
    ]);
    return devices.rows.map((d) => {
      const linked = bindings.rows.filter(
        (b) => b.collected_device_id === d.id && b.status !== 'locally_removed',
      );
      const statuses = linked.map((b) => b.status);
      const state: CollectedDeviceStatus = statuses.includes('ready')
        ? 'ready'
        : statuses.includes('registering')
          ? 'registering'
          : statuses.includes('apple_processing')
            ? 'apple_processing'
            : statuses.includes('certificate_required')
              ? 'certificate_required'
              : statuses.includes('collected')
                ? 'collected'
                : statuses.includes('not_registered')
                  ? 'not_registered'
                  : statuses.includes('disabled')
                    ? 'disabled'
                    : statuses.includes('ineligible')
                      ? 'ineligible'
                      : prior.rows.some((b) => b.collected_device_id === d.id)
                        ? 'connection_unavailable'
                        : 'collected';
      return {
        id: d.id,
        name: d.name,
        udid: mask(d.udid),
        product: d.product,
        osVersion: d.os_version,
        createdAt: Number(d.created_at),
        verifiedAt: Number(d.enrollment_verified_at),
        status: state,
        bindings: linked
          .filter((b) => b.device_id !== null)
          .map((b) => ({
            deviceId: b.device_id!,
            connectionId: b.connection_id,
            teamId: b.team_id,
            generation: b.generation,
            status: b.status,
            shared: b.shared,
          })),
      };
    });
  }
  async reveal(owner: string, device: string) {
    const found = await this.db.query<{
      id: string;
      udid: string;
    }>(
      'SELECT d.id,d.udid FROM collected_devices d JOIN users u ON u.id=d.owner_id WHERE d.id=$1 AND d.owner_id=$2 AND u.deleted_at IS NULL',
      [device, owner],
    );
    if (!found.rows[0]) throw new Failure('DEVICE_NOT_FOUND', 404);
    return found.rows[0];
  }
  async reconcileOwner(owner: string): Promise<void> {
    await this.seed(owner);
    await this.runDue(20, owner);
  }
  async reconcileDue(limit = 20): Promise<void> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100)
      throw new Failure('INVALID_RECONCILIATION_LIMIT');
    const owners = await this.db.query<{
      owner_id: string;
    }>(
      `SELECT DISTINCT owner_id FROM collected_devices d JOIN users u ON u.id=d.owner_id WHERE u.deleted_at IS NULL AND u.blocked_at IS NULL`,
    );
    for (const owner of owners.rows) await this.seed(owner.owner_id);
    await this.runDue(limit);
  }
  private binding(check: CheckRow): AppleAccess {
    return {
      ownerId: check.owner_id,
      connectionId: check.connection_id,
      connectionOwnerId: check.connection_owner_id,
      generation: check.generation,
      accessGrantId: check.access_grant_id,
      accessGrantGeneration: check.access_grant_generation,
    };
  }
  private async runDue(limit: number, owner?: string) {
    // Claim just one at a time so a slow provider does not exhaust leases on queued work.
    for (let n = 0; n < limit; n++) {
      const lease = token();
      const next = await this.db.query<CheckRow>(
        `WITH candidate AS(SELECT k.id FROM device_collection_checks k WHERE k.next_check_at<=$1 AND k.lease_until<=$1 AND ${currentCheck} AND ($4::text IS NULL OR k.owner_id=$4) ORDER BY k.next_check_at,k.id LIMIT 1 FOR UPDATE SKIP LOCKED)
    UPDATE device_collection_checks k SET lease_token=$2,lease_until=$3 FROM candidate WHERE k.id=candidate.id RETURNING k.*`,
        [this.now(), lease, this.now() + 120000, owner ?? null],
      );
      const check = next.rows[0];
      if (!check) return;
      try {
        const device = await this.materialize(check);
        if (!device) {
          await this.finish(check, 'locally_removed', 300000);
          continue;
        }
        const result = await this.onboarding.poll(check.owner_id, device, {
          checkId: check.id,
          token: check.lease_token,
        });
        await this.finish(
          check,
          result.status,
          ['registering', 'apple_processing', 'collected', 'certificate_required'].includes(
            result.status,
          )
            ? 30000
            : 300000,
        );
      } catch (error) {
        const code = error instanceof Failure ? error.message : 'DEVICE_CHECK_FAILED';
        if (code === 'APPLE_DEVICE_NOT_FOUND') {
          const pending = await this.db.query<{
            status: string;
          }>(
            `SELECT d.status FROM device_collection_checks k JOIN devices d ON d.id=k.device_id AND d.owner_id=k.owner_id
      WHERE k.id=$1 AND k.lease_token=$2 AND k.lease_until>$3 AND d.status IN('registering','apple_processing','certificate_required') AND d.connection_generation=k.generation AND d.connection_owner_id=k.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM k.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM k.access_grant_generation AND ${currentCheck}
      AND EXISTS(SELECT 1 FROM device_registration_operations o WHERE o.connection_id=k.connection_id AND o.generation=k.generation AND o.udid_hash=d.udid_hash AND o.state IN('submitted','unknown','complete'))`,
            [check.id, lease, this.now()],
          );
          if (pending.rows[0]) {
            await this.finish(check, pending.rows[0].status, 30000);
            continue;
          }
          await this.db.query(
            `UPDATE devices d SET status='collected',selected=false,apple_resource_id=NULL FROM device_collection_checks k WHERE k.id=$1 AND k.lease_token=$2 AND k.lease_until>$3 AND d.id=k.device_id AND d.owner_id=k.owner_id AND d.status!='locally_removed' AND d.connection_generation=k.generation AND d.connection_owner_id=k.connection_owner_id AND d.access_grant_id IS NOT DISTINCT FROM k.access_grant_id AND d.access_grant_generation IS NOT DISTINCT FROM k.access_grant_generation AND ${currentCheck}`,
            [check.id, lease, this.now()],
          );
          await this.finish(check, 'not_registered', 120000);
        } else
          await this.db.query(
            `UPDATE device_collection_checks k SET failures=failures+1,last_error=$3,next_check_at=$4,lease_token=NULL,lease_until=0 WHERE id=$1 AND lease_token=$2`,
            [
              check.id,
              lease,
              code,
              this.now() + Math.min(900000, 30000 * 2 ** Math.min(check.failures, 5)),
            ],
          );
      }
    }
  }
  private async materialize(check: CheckRow) {
    return this.db.transaction(async (tx) => {
      await tx.query('SELECT id FROM connections WHERE id=$1 FOR UPDATE', [check.connection_id]);
      await assertAppleAccess(tx, this.binding(check));
      const current = (
        await tx.query<CheckRow>(
          'SELECT * FROM device_collection_checks WHERE id=$1 AND lease_token=$2 AND lease_until>$3 FOR UPDATE',
          [check.id, check.lease_token, this.now()],
        )
      ).rows[0];
      if (
        !current ||
        current.generation !== check.generation ||
        current.access_grant_id !== check.access_grant_id ||
        current.access_grant_generation !== check.access_grant_generation
      )
        throw new Failure('CONNECTION_CHANGED', 409);
      const collected = (
        await tx.query<CollectionRow>(
          'SELECT d.* FROM collected_devices d JOIN users u ON u.id=d.owner_id WHERE d.id=$1 AND d.owner_id=$2 AND u.deleted_at IS NULL',
          [check.collected_device_id, check.owner_id],
        )
      ).rows[0];
      if (!collected) throw new Failure('DEVICE_NOT_FOUND', 404);
      const stored = await tx.query<{
        id: string;
        status: string;
      }>(
        `INSERT INTO devices(id,owner_id,connection_id,name,status,os_version,udid,udid_hash,connection_generation,enrollment_verified_at,enrollment_cms_sha256,connection_owner_id,access_grant_id,access_grant_generation)
    VALUES($1,$2,$3,$4,'collected',$5,$6,$7,$8,$9,$10,$11,$12,$13)
    ON CONFLICT(owner_id,connection_id,udid_hash) WHERE udid_hash IS NOT NULL DO UPDATE SET
     status=CASE WHEN devices.status='locally_removed' THEN devices.status WHEN devices.connection_generation=$8 AND devices.connection_owner_id=$11 AND devices.access_grant_id IS NOT DISTINCT FROM $12 AND devices.access_grant_generation IS NOT DISTINCT FROM $13 THEN devices.status ELSE 'collected' END,
     apple_resource_id=CASE WHEN devices.connection_generation=$8 AND devices.connection_owner_id=$11 AND devices.access_grant_id IS NOT DISTINCT FROM $12 AND devices.access_grant_generation IS NOT DISTINCT FROM $13 THEN devices.apple_resource_id ELSE NULL END,
     connection_generation=$8,connection_owner_id=$11,access_grant_id=$12,access_grant_generation=$13,enrollment_verified_at=$9,enrollment_cms_sha256=$10,os_version=COALESCE(devices.os_version,$5)
    RETURNING id,status`,
        [
          id(),
          check.owner_id,
          check.connection_id,
          collected.name,
          collected.os_version,
          collected.udid,
          collected.udid_hash,
          check.generation,
          collected.enrollment_verified_at,
          collected.enrollment_cms_sha256,
          check.connection_owner_id,
          check.access_grant_id,
          check.access_grant_generation,
        ],
      );
      await tx.query(
        'UPDATE device_collection_checks SET device_id=$3 WHERE id=$1 AND lease_token=$2',
        [check.id, check.lease_token, stored.rows[0].id],
      );
      return stored.rows[0].status === 'locally_removed' ? null : stored.rows[0].id;
    });
  }
  private async finish(check: CheckRow, status: string, delay: number) {
    const updated = await this.db.query(
      `UPDATE device_collection_checks k SET status=$3,last_checked_at=$4,next_check_at=$5,failures=0,last_error=NULL,lease_token=NULL,lease_until=0 WHERE k.id=$1 AND k.lease_token=$2 AND k.lease_until>$4 AND k.generation=$6 AND k.access_grant_id IS NOT DISTINCT FROM $7 AND k.access_grant_generation IS NOT DISTINCT FROM $8 AND ${currentCheck} RETURNING id`,
      [
        check.id,
        check.lease_token,
        status,
        this.now(),
        this.now() + delay,
        check.generation,
        check.access_grant_id,
        check.access_grant_generation,
      ],
    );
    if (!updated.rows.length) throw new Failure('CONNECTION_CHANGED', 409);
  }
}
