import { createHash } from 'node:crypto';
import { chmod, mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

// Reviewed publisher builds dated 2026-09-20. A changed download requires a
// deliberate hash update; it is never executed merely because the URL is stable.
const builds = {
  'linux-x64': {
    file: 'isignkit-x86_64-unknown-linux-gnu',
    sha256: '2479f2125c36a0492e0082bc6ccdb5f5a8773a4dd03b094eccca19b08c44c91b',
  },
  'darwin-arm64': {
    file: 'isignkit-macos',
    sha256: '300d02a8b04010134b449d2a5a425f008e3512898ca09c7957326ab173becf43',
  },
  'darwin-x64': {
    file: 'isignkit-macos',
    sha256: '300d02a8b04010134b449d2a5a425f008e3512898ca09c7957326ab173becf43',
  },
};

const build = builds[`${process.platform}-${process.arch}`];
if (!build) throw new Error('ISIGNKIT_PLATFORM_UNSUPPORTED: use Linux x64 or macOS');
const directory = fileURLToPath(new URL('../.tools/', import.meta.url));
const binary = path.join(directory, 'isignkit');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
let installed = false;
try {
  installed = digest(await readFile(binary)) === build.sha256;
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
if (!installed) {
  const response = await fetch(`https://rejail.ru/dl/iapps/isignkit/${build.file}`, {
    signal: AbortSignal.timeout(60000),
  });
  if (!response.ok) throw new Error('ISIGNKIT_DOWNLOAD_FAILED');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (digest(bytes) !== build.sha256) throw new Error('ISIGNKIT_CHECKSUM_MISMATCH');
  await mkdir(directory, { recursive: true });
  const temporary = path.join(directory, `isignkit-${process.pid}.tmp`);
  try {
    await writeFile(temporary, bytes, { mode: 0o755 });
    await rename(temporary, binary);
  } finally {
    await rm(temporary, { force: true });
  }
}
await chmod(binary, 0o755);
console.log('Verified isignkit installed');
