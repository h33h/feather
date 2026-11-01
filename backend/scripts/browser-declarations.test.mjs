import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isEphemeralDist, stableDeclarations } from './browser-declarations.mjs';

test('rebases every ephemeral snapshot to the stable generated type directory', () => {
  const snapshot =
    '/// <reference types="next" />\n' +
    'import "./.next-browser-first/dev/types/routes.d.ts";\n' +
    "import './build/.next-safety-second/types/root-params.d.ts';\n";
  assert.equal(
    stableDeclarations(snapshot, '.next-custom/dev/types'),
    '/// <reference types="next" />\n' +
      'import "./.next-custom/dev/types/routes.d.ts";\n' +
      "import './.next-custom/dev/types/root-params.d.ts';\n",
  );
});

test('preserves ordinary declaration snapshots exactly', () => {
  const snapshot = 'import "./.next-custom/dev/types/routes.d.ts";\n// Keep this note.\n';
  assert.equal(stableDeclarations(snapshot, '.next/types'), snapshot);
});

test('recognizes inherited test profiles and preserves stable profiles', () => {
  for (const directory of [
    '.next-browser-first',
    '.next-safety-second',
    'build/.next-browser-third',
  ])
    assert.equal(isEphemeralDist(directory), true);
  for (const directory of ['.next', '.next-custom', 'build/next'])
    assert.equal(isEphemeralDist(directory), false);
});
