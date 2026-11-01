import type { QueryDatabase } from '../shared/database';
import type { JobsActions } from '../signing/jobs-actions';
import { Failure } from '../shared/errors';
type DeviceChecks = { checkRegistered(owner: string, device: string): Promise<unknown> };
export class JobRequests {
  constructor(
    private db: QueryDatabase,
    private actions: JobsActions,
    private devices?: DeviceChecks,
  ) {}
  async ensure(owner: string, input: { uploadId: string; deviceId?: string; key: string }) {
    const available = (
      await this.db.query<{ id: string; selected: boolean }>(
        "SELECT id,selected FROM signing_devices WHERE owner_id=$1 AND status='ready' ORDER BY selected DESC,id",
        [owner],
      )
    ).rows;
    const device =
      input.deviceId ??
      available.find((d) => d.selected)?.id ??
      (available.length === 1 ? available[0].id : undefined);
    if (!device) throw new Failure('DEVICE_SELECTION_REQUIRED', 409);
    await this.devices?.checkRegistered(owner, device);
    return this.actions.ensure(owner, { ...input, deviceId: device });
  }
  async retry(owner: string, job: string) {
    return this.actions.retry(owner, job);
  }
}
