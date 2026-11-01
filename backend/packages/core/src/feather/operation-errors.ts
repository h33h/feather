import { Failure } from '../shared';
/** Only explicit rejection responses prove an Apple mutation did not occur. */
export function assetFailure(error: unknown) {
  return error instanceof Failure &&
    ['APPLE_OPERATION_REJECTED', 'APPLE_ACCESS_ACTION_REQUIRED', 'APPLE_RATE_LIMITED'].includes(
      error.code,
    )
    ? error.code
    : null;
}
// The attested CMS worker has a 120-second deadline. Renew at durable checkpoints.
export const ASSET_LEASE_MS = 150000;
