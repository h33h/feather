import { lockPrincipalConnections } from '../apple/access';
import { invalidateAccess } from '../apple/access-lifecycle';
import type { Database } from '../shared/database';
import { Failure } from '../shared/index';
export class DeviceActions {
  constructor(
    public db: Database,
    private clock: () => number,
  ) {}
  get now() {
    return this.clock();
  }
  async selectDevice(ownerId: string, deviceId: string) {
    await this.db.transaction(async (tx) => {
      const row = await tx.query(
        "SELECT id FROM devices WHERE id=$1 AND owner_id=$2 AND status='ready'",
        [deviceId, ownerId],
      );
      if (!row.rows.length) throw new Failure('NOT_FOUND', 404);
      await tx.query('UPDATE devices SET selected=false WHERE owner_id=$1', [ownerId]);
      await tx.query('UPDATE devices SET selected=true WHERE id=$1 AND owner_id=$2', [
        deviceId,
        ownerId,
      ]);
    });
  }
  async removeIdentity(ownerId: string, collectedId: string) {
    await this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, ownerId);
      const identity = (
        await tx.query<{ udid_hash: string }>(
          'SELECT udid_hash FROM collected_devices WHERE id=$1 AND owner_id=$2 FOR UPDATE',
          [collectedId, ownerId],
        )
      ).rows[0];
      if (!identity) throw new Failure('NOT_FOUND', 404);
      const devices = (
        await tx.query<{ id: string }>(
          'SELECT id FROM devices WHERE owner_id=$1 AND udid_hash=$2',
          [ownerId, identity.udid_hash],
        )
      ).rows;
      for (const device of devices)
        await invalidateAccess(tx, { deviceId: device.id }, 'DEVICE_REMOVED', this.now);
      await tx.query(
        "UPDATE devices SET status='locally_removed',selected=false WHERE owner_id=$1 AND udid_hash=$2",
        [ownerId, identity.udid_hash],
      );
      await tx.query('DELETE FROM collected_devices WHERE id=$1 AND owner_id=$2', [
        collectedId,
        ownerId,
      ]);
    });
  }
  async removeDevice(ownerId: string, deviceId: string) {
    await this.db.transaction(async (tx) => {
      await lockPrincipalConnections(tx, ownerId);
      const device = (
        await tx.query<{ udid_hash: string | null }>(
          "UPDATE devices SET status='locally_removed',selected=false WHERE id=$1 AND owner_id=$2 RETURNING udid_hash",
          [deviceId, ownerId],
        )
      ).rows[0];
      if (!device) throw new Failure('NOT_FOUND', 404);
      await invalidateAccess(tx, { deviceId }, 'DEVICE_REMOVED', this.now);
      if (device.udid_hash)
        await tx.query('DELETE FROM collected_devices WHERE owner_id=$1 AND udid_hash=$2', [
          ownerId,
          device.udid_hash,
        ]);
    });
  }
}
