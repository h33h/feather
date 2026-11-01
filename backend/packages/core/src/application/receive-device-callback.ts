import type { DeviceCollection } from '../devices/collection';
import type { DeviceOnboarding } from '../devices/onboarding';
import type { ProfileDiagnostics } from '../devices/profile-diagnostics';
import { Failure } from '../shared/errors';
export class ReceiveDeviceCallback {
  constructor(
    private collections?: Pick<DeviceCollection, 'hasChallenge' | 'callback'>,
    private devices?: Pick<DeviceOnboarding, 'callback'>,
    private diagnostics?: Pick<ProfileDiagnostics, 'capture'>,
  ) {}
  async run(challenge: string, packet: Buffer) {
    const collected = await this.collections?.hasChallenge(challenge);
    if (collected && this.collections) {
      try {
        await this.collections.callback(challenge, packet);
      } catch (problem) {
        if (problem instanceof Failure)
          await this.diagnostics?.capture(challenge, packet, problem.code).catch(() => {});
        throw problem;
      }
    } else if (this.devices) await this.devices.callback(challenge, packet);
    else throw new Failure('CHALLENGE_EXPIRED_OR_USED', 410);
  }
}
