import { mkdir, open, lstat } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import type { Database } from '../shared/database';
import { ProviderError } from '../shared/errors';
/** Only invoked by explicit operator init-vault, never application startup. */
export async function initializePersonalVault(
  db: Database,
  config: {
    keyFile: string;
  },
) {
  if ((await db.query('SELECT id FROM secrets LIMIT 1')).rows.length)
    throw new ProviderError('EMPTY_VAULT_REQUIRED');
  const files = [config.keyFile];
  for (const file of files) {
    try {
      await lstat(file);
      throw new ProviderError('VAULT_STATE_ALREADY_EXISTS');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }
  }
  await mkdir(path.dirname(config.keyFile), { recursive: true, mode: 0o700 });
  const key = randomBytes(32);
  try {
    for (const file of files) {
      const handle = await open(
        file,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o600,
      );
      try {
        await handle.writeFile(key);
        await handle.sync();
      } finally {
        await handle.close();
      }
      const parent = await open(path.dirname(file), constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        await parent.sync();
      } finally {
        await parent.close();
      }
    }
  } finally {
    key.fill(0);
  }
}
