import { loadPrivateEnvironment } from '../packages/core/src/infrastructure/private-environment';
import { spawn } from 'node:child_process';
async function main() {
  if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('NODE_22_REQUIRED');
  await loadPrivateEnvironment('/run/isign/server.env', process.env);
  const child = spawn(
    process.execPath,
    ['node_modules/next/dist/bin/next', 'start', 'web', '--hostname', '0.0.0.0'],
    { stdio: 'inherit', env: process.env },
  );
  for (const signal of ['SIGTERM', 'SIGINT'] as const) process.on(signal, () => child.kill(signal));
  child.on('exit', (code) => {
    process.exitCode = code ?? 1;
  });
}
main().catch(() => {
  console.error('PERSONAL_START_FAILED');
  process.exitCode = 1;
});
