import { connectAutomatically } from '../apple/automatic-connection';
import type { AppleOnboarding } from '../apple/onboarding';
export class ConnectApple {
  constructor(
    private onboarding: AppleOnboarding,
    private bootstrap: Parameters<typeof connectAutomatically>[1],
  ) {}
  run(owner: string, input: Parameters<typeof connectAutomatically>[3]) {
    return connectAutomatically(this.onboarding, this.bootstrap, owner, input);
  }
}
