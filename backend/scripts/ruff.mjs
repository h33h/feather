import { existsSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const source = fileURLToPath(new URL('../', import.meta.url));
const ruff = path.join(
  source,
  '.venv',
  process.platform === 'win32' ? 'Scripts/ruff.exe' : 'bin/ruff',
);
if (!existsSync(ruff)) {
  console.error(
    'Ruff is missing. Run pnpm setup:runner from the repository root to install Python development tools.',
  );
  process.exit(1);
}
const [command, ...args] = process.argv.slice(2);
const result = spawnSync(ruff, [command, '--config', path.join(source, '../ruff.toml'), ...args], {
  stdio: 'inherit',
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
