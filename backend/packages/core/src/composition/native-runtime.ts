import type { Database } from '../shared/database';
import { NativeSessions } from '../auth/native-sessions';
import { assertInitializedDatabase } from '../infrastructure/database-init';
import { Failure } from '../shared';
export async function createNativeAuth(
  db: Database,
  env: Record<string, string | undefined>,
  origin: string,
): Promise<NativeSessions | undefined> {
  const flag = env.ISIGN_FEATHER_ENABLED;
  if (flag === undefined || flag === 'false') return undefined;
  if (flag !== 'true') throw new Failure('FEATHER_CONFIGURATION_INVALID', 503);
  await assertInitializedDatabase(db, { native: true });
  return new NativeSessions(db, { origin, callback: 'isign-feather://auth/callback' });
}
