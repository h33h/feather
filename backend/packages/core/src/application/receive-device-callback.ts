import type { DeviceCollection } from '../devices/collection';
import type { ProfileDiagnostics } from '../devices/profile-diagnostics';
import { Failure } from '../shared/errors';
export class ReceiveDeviceCallback {
  constructor(
    private collections: Pick<DeviceCollection, 'callback'>,
    private diagnostics?: Pick<ProfileDiagnostics, 'capture'>,
  ) {}
  async run(challenge: string, packet: Buffer) {
    try {
      await this.collections.callback(challenge, packet);
    } catch (problem) {
      if (problem instanceof Failure)
        await this.diagnostics?.capture(challenge, packet, problem.code).catch(() => {});
      throw problem;
    }
  }
}
