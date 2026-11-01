import type { AppleOnboarding } from './onboarding';
import { Failure } from '../shared/errors';
export async function connectAutomatically(
  onboarding: AppleOnboarding,
  bootstrap: ((owner: string) => Promise<unknown>) | undefined,
  owner: string,
  input: Parameters<AppleOnboarding['connect']>[1],
) {
  let connected: unknown;
  try {
    connected = await onboarding.connect(owner, input);
  } catch (error) {
    if (
      !(error instanceof Failure) ||
      !['TEAM_PROOF_REQUIRED', 'CERTIFICATE_REQUIRED'].includes(error.code)
    )
      throw error;
    if (!bootstrap) throw new Failure('BOOTSTRAP_BROKER_UNAVAILABLE', 503);
  }
  if (!bootstrap) throw new Failure('BOOTSTRAP_BROKER_UNAVAILABLE', 503);
  try {
    return await bootstrap(owner);
  } catch (error) {
    if (error instanceof Failure && error.code === 'BOOTSTRAP_NOT_REQUIRED') return connected;
    throw error;
  }
}
