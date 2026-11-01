import { Failure } from '../shared/index';
import { decryptGBoxPayload } from './gbox-decrypt';
export const CURRENT_GBOX_URL =
  'https://github.com/polyatar/kikspaq/releases/download/dosa/jngzxskldfjkdsljfksjdkflsjdkfljsdkfjdskfj.json';
export const CURRENT_PACKAGE_HOSTS = [
  'storage.iapps.rejail.ru',
  'github.com',
  'release-assets.githubusercontent.com',
  'raw.githubusercontent.com',
];
export async function decodeFeed(bytes: Buffer, sourceUrl: string): Promise<unknown> {
  let input: unknown;
  try {
    input = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Failure('UNSUPPORTED_GBOX_SCHEMA');
  }
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new Failure('UNSUPPORTED_GBOX_SCHEMA');
  const repository = input as { appRepositories?: unknown; apps?: unknown };
  if (Array.isArray(repository.appRepositories) || Array.isArray(repository.apps)) return input;
  // The built-in publisher is the only encrypted source we authorize. Other
  // sources still need a plain GBox export and their own artifact-host trust.
  if (sourceUrl !== CURRENT_GBOX_URL) throw new Failure('GBOX_EXPORT_CHANGED', 409);
  if (typeof repository.appRepositories !== 'string') throw new Failure('UNSUPPORTED_GBOX_SCHEMA');
  return { ...input, appRepositories: await decryptGBoxPayload(bytes) };
}
