import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

if (process.env.NODE_ENV === 'production') process.exit(0);

const source = fileURLToPath(new URL('../', import.meta.url));
const root = path.dirname(source.replace(/[\\/]$/, ''));
function run(command, args, cwd = source) {
  const result = spawnSync(command, args, { cwd, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

if (process.env.HUSKY !== '0' && !process.env.CI) {
  const git = spawnSync('git', ['rev-parse', '--git-dir'], { cwd: root, stdio: 'ignore' });
  if (git.status === 0) run(process.execPath, [path.join(root, 'node_modules/husky/bin.js')], root);
}
