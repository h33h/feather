import { expect, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
const files = (root: string): string[] =>
  readdirSync(root, { withFileTypes: true }).flatMap((item) =>
    item.isDirectory() ? files(join(root, item.name)) : [join(root, item.name)],
  );
it('installer and auth import shared facilities without retired store dependencies', () => {
  for (const folder of ['installer', 'auth'])
    for (const path of files(`web/src/features/${folder}`)) {
      expect(readFileSync(path, 'utf8'), path).not.toMatch(
        /(?:from\s*|import\s*)['"][^'"]*store\//,
      );
    }
});
it('shared facilities have no feature imports', () => {
  for (const path of files('web/src/shared'))
    expect(readFileSync(path, 'utf8'), path).not.toMatch(
      /(?:from\s*|import\s*)['"][^'"]*features\//,
    );
});
it('contracts are neutral and independent from application layers', () => {
  expect(files('backend/packages/contracts').length).toBeGreaterThan(0);
  for (const path of files('backend/packages/contracts'))
    expect(readFileSync(path, 'utf8'), path).not.toMatch(
      /(?:from\s*|import\s*)['"](?:[^'"]*(?:core|apps|web)|node:|react)/,
    );
});
