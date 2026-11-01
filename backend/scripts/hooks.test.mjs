import assert from 'node:assert/strict';
import {
  mkdtempSync,
  realpathSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  copyFileSync,
  symlinkSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const source = fileURLToPath(new URL('../', import.meta.url));
const project = path.dirname(source.replace(/[\\/]$/, ''));

function fixture() {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'isign-hooks-')));
  const run = (command, args, input) =>
    spawnSync(command, args, {
      cwd: root,
      encoding: 'utf8',
      input,
      env: { ...process.env, HUSKY: '1' },
    });
  const git = (...args) => {
    const result = run('git', args);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    return result.stdout.trim();
  };
  git('init', '--quiet', '--initial-branch=main');
  git('config', 'user.name', 'Hook Test');
  git('config', 'user.email', 'hook-test@example.invalid');
  git('config', 'commit.gpgsign', 'false');
  mkdirSync(path.join(root, '.husky'));
  mkdirSync(path.join(root, 'backend/scripts'), { recursive: true });
  mkdirSync(path.join(root, 'web/src/app'), { recursive: true });
  for (const name of [
    'prettier.config.mjs',
    '.prettierignore',
    '.editorconfig',
    'ruff.toml',
    'lint-staged.config.mjs',
  ])
    copyFileSync(path.join(project, name), path.join(root, name));
  copyFileSync(path.join(project, '.husky/pre-commit'), path.join(root, '.husky/pre-commit'));
  for (const name of ['lint-staged-js.mjs', 'ruff.mjs'])
    copyFileSync(path.join(source, 'scripts', name), path.join(root, 'backend/scripts', name));
  copyFileSync(path.join(project, 'eslint.config.mjs'), path.join(root, 'eslint.config.mjs'));
  writeFileSync(path.join(root, 'package.json'), '{"type":"module"}\n');
  copyFileSync(path.join(project, '.gitignore'), path.join(root, '.gitignore'));
  copyFileSync(path.join(source, '.gitignore'), path.join(root, 'backend/.gitignore'));
  symlinkSync(path.join(project, 'node_modules'), path.join(root, 'node_modules'), 'dir');
  symlinkSync(path.join(source, '.venv'), path.join(root, 'backend/.venv'), 'dir');
  const installed = run(process.execPath, [path.join(project, 'node_modules/husky/bin.js')]);
  assert.equal(installed.status, 0, installed.stderr);
  return { root, run, git, close: () => rmSync(root, { recursive: true, force: true }) };
}

test('real pre-commit hook formats staged TypeScript, Python and root YAML', () => {
  const f = fixture();
  try {
    writeFileSync(
      path.join(f.root, 'backend/sample with spaces.ts'),
      'export const value={answer:42};\n',
    );
    writeFileSync(path.join(f.root, 'backend/sample.py'), 'def add(a,b):return a+b\n');
    writeFileSync(path.join(f.root, 'example.yml'), 'value: {answer: 42}\n');
    f.git('add', '.');
    f.git('commit', '-m', 'test formatted files');
    assert.equal(
      f.git('show', 'HEAD:backend/sample with spaces.ts'),
      'export const value = { answer: 42 };',
    );
    assert.equal(f.git('show', 'HEAD:backend/sample.py'), 'def add(a, b):\n    return a + b');
    assert.equal(f.git('status', '--porcelain'), '');
  } finally {
    f.close();
  }
});

test('real hook leaves iOS Python and JSON files unchanged', () => {
  const f = fixture();
  try {
    const directory = path.join(f.root, 'ios/Tests');
    mkdirSync(directory, { recursive: true });
    const python = 'def keep_ios_style(a,b):return a+b\n';
    const json = '{"keep":"upstream style"}\n';
    writeFileSync(path.join(directory, 'sample.py'), python);
    writeFileSync(path.join(directory, 'sample.json'), json);
    f.git('add', '.');
    f.git('commit', '-m', 'test iOS tooling boundary');
    assert.equal(f.git('show', 'HEAD:ios/Tests/sample.py'), python.trim());
    assert.equal(f.git('show', 'HEAD:ios/Tests/sample.json'), json.trim());
    assert.equal(f.git('status', '--porcelain'), '');
  } finally {
    f.close();
  }
});

test('real hook preserves unstaged edits in a partially staged file', () => {
  const f = fixture();
  try {
    const file = path.join(f.root, 'backend/sample.ts');
    writeFileSync(file, 'export const first = 1;\n\nexport const second = 2;\n');
    f.git('add', '.');
    f.git('commit', '-m', 'test baseline');
    writeFileSync(file, 'export const first=11;\n\nexport const second = 2;\n');
    f.git('add', 'backend/sample.ts');
    writeFileSync(file, 'export const first=11;\n\nexport const second=22;\n');
    f.git('commit', '-m', 'test partial stage');
    assert.equal(
      f.git('show', 'HEAD:backend/sample.ts'),
      'export const first = 11;\n\nexport const second = 2;',
    );
    assert.match(readFileSync(file, 'utf8'), /second\s*=\s*22/);
    assert.equal(f.git('status', '--porcelain'), 'M backend/sample.ts');
  } finally {
    f.close();
  }
});

test('real hook blocks malformed code and retains the staged changes', () => {
  const f = fixture();
  try {
    writeFileSync(path.join(f.root, 'backend/sample.ts'), 'export const value = 1;\n');
    f.git('add', '.');
    f.git('commit', '-m', 'test baseline');
    const head = f.git('rev-parse', 'HEAD');
    writeFileSync(path.join(f.root, 'backend/sample.ts'), 'export const value = ;\n');
    f.git('add', 'backend/sample.ts');
    const result = f.run('git', ['commit', '-m', 'must fail']);
    assert.notEqual(result.status, 0);
    assert.equal(f.git('rev-parse', 'HEAD'), head);
    assert.equal(f.git('show', ':backend/sample.ts'), 'export const value = ;');
  } finally {
    f.close();
  }
});

test('formatters skip Git-ignored private JSON files', () => {
  const f = fixture();
  try {
    const file = path.join(f.root, 'backend/deploy/personal/secrets/example.json');
    mkdirSync(path.dirname(file), { recursive: true });
    const raw = '{"fixture":"synthetic-only"}\n';
    writeFileSync(file, raw);
    const result = f.run(path.join(project, 'node_modules/.bin/prettier'), [
      '--write',
      file,
      '--ignore-path',
      '.prettierignore',
      '--ignore-path',
      '.gitignore',
    ]);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(file, 'utf8'), raw);
  } finally {
    f.close();
  }
});
