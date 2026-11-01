import { open } from 'node:fs/promises';
import { constants } from 'node:fs';
import { ProviderError } from '../shared/errors';
export async function loadPrivateEnvironment(
  file: string,
  env: Record<string, string | undefined>,
) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > 16384)
      throw new ProviderError('PRIVATE_CONFIG_REQUIRED');
    const text = await handle.readFile('utf8');
    const values: Record<string, string> = {};
    for (const line of text.split('\n')) {
      if (!line || line.startsWith('#')) continue;
      const match = line.match(/^(DATABASE_URL|ISIGN_RUNNER_TOKEN|ISIGN_RUNNER_PROOF_KEY)=(.+)$/);
      if (!match || values[match[1]] || /[\r\0]/.test(match[2]))
        throw new ProviderError('PRIVATE_CONFIG_INVALID');
      values[match[1]] = match[2];
    }
    for (const [key, value] of Object.entries(values)) env[key] = value;
  } finally {
    await handle.close();
  }
}
