import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
const python = 'backend/.venv/bin/python';
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
if (!existsSync(python)) run('python3', ['-m', 'venv', 'backend/.venv']);
run(python, [
  '-m',
  'pip',
  'install',
  '--disable-pip-version-check',
  '-r',
  'backend/requirements-dev.txt',
]);
