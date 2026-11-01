import { spawn } from 'node:child_process';
import { access, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isEphemeralDist, stableDeclarations } from './browser-declarations.mjs';

const port = process.argv[2] ?? '3000';
const declarations = fileURLToPath(new URL('../../web/next-env.d.ts', import.meta.url));
const originalDeclarations = await readFile(declarations, 'utf8');
const inheritedDist = process.env.ISIGN_NEXT_DIST_DIR ?? '.next';
const stableDist = isEphemeralDist(inheritedDist) ? '.next' : inheritedDist;
const directory = await mkdtemp(path.join(tmpdir(), 'isign-browser-'));
const distName = '.next-browser-' + path.basename(directory);
const distDirectory = fileURLToPath(new URL('../../web/' + distName, import.meta.url));
const child = spawn(
  process.execPath,
  [fileURLToPath(new URL('./local-server.mjs', import.meta.url)), '--port', port],
  {
    stdio: 'inherit',
    detached: process.platform !== 'win32',
    env: {
      ...process.env,
      ISIGN_RUNTIME: 'personal',
      ISIGN_ORIGIN: 'http://localhost:' + port,
      ISIGN_NEXT_DIST_DIR: distName,
    },
  },
);
let stopping = false;
let timer;
function signalChild(signal) {
  try {
    if (process.platform === 'win32') child.kill(signal);
    else process.kill(-child.pid, signal);
  } catch (error) {
    if (error.code !== 'ESRCH') throw error;
  }
}
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => {
    if (stopping) return;
    stopping = true;
    signalChild('SIGTERM');
    timer = setTimeout(() => signalChild('SIGKILL'), 30000);
    timer.unref();
  });
}
async function cleanup() {
  await Promise.all(
    [directory, distDirectory].map((value) => rm(value, { recursive: true, force: true })),
  );
  const stablePrefix = stableDist.replaceAll('\\', '/');
  const devTypes = path.posix.join(stablePrefix, 'dev/types');
  const typesDirectory = await access(
    path.resolve(path.dirname(declarations), devTypes, 'routes.d.ts'),
  )
    .then(() => devTypes)
    .catch(() => path.posix.join(stablePrefix, 'types'));
  // Restore only our generated declarations; a running dev server may have replaced them.
  if ((await readFile(declarations, 'utf8')).includes(distName)) {
    // A cached snapshot can belong to another test that has already removed its output.
    await writeFile(declarations, stableDeclarations(originalDeclarations, typesDirectory));
  }
}
child.once('error', async (error) => {
  console.error(error);
  await cleanup();
  process.exitCode = 1;
});
child.once('exit', async (code) => {
  clearTimeout(timer);
  await cleanup();
  process.exitCode = code ?? 1;
});
