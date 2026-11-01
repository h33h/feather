import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../../', import.meta.url));
const files = process.argv.slice(2).filter((file) => path.resolve(file).startsWith(source));
if (!files.length) process.exit(0);
const result = spawnSync(
  process.execPath,
  [path.join(source, 'node_modules/eslint/bin/eslint.js'), '--fix', ...files],
  { cwd: source, stdio: 'inherit' },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
