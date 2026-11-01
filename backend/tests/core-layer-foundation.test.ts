import { createHmac } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, it } from 'vitest';

const root = fileURLToPath(new URL('../packages/core/src/', import.meta.url));
const source = (path: string) => readFileSync(root + path, 'utf8');

it('keeps runner contracts and canonical encoding neutral and composition outside application', () => {
  for (const path of [
    'shared/runner-contracts.ts',
    'shared/canonical-json.ts',
    'infrastructure/broker-rpc.ts',
    'infrastructure/collection-cms.ts',
    'composition/personal-kernel.ts',
    'composition/signing-runtime.ts',
    'apple/request-port.ts',
  ])
    expect(existsSync(root + path), path).toBe(true);
  for (const path of [
    'application/personal-kernel.ts',
    'application/signing-runtime.ts',
    'devices/cms-rpc.ts',
    'devices/collection-cms.ts',
  ])
    expect(existsSync(root + path), path).toBe(false);
  for (const path of ['shared/runner-contracts.ts', 'shared/canonical-json.ts'])
    expect(source(path)).not.toMatch(
      /from ['"][^'"]*(?:signing|apple|devices|infrastructure|application|composition)\//,
    );
  for (const entry of readdirSync(root, { recursive: true })) {
    const path = String(entry);
    if (!path.endsWith('.ts')) continue;
    const text = source(path);
    const imports = text.matchAll(/import\s+(?:type\s+)?\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/gs);
    for (const [, names, module] of imports)
      if (module.endsWith('/publisher'))
        expect(names, path).not.toMatch(/\b(?:ExecutorGrant|VerifiedReport|canonicalReport)\b/);
    if (path.startsWith('application/') || path.startsWith('apple/') || path.startsWith('devices/'))
      expect(text, path).not.toMatch(/from ['"][^'"]*(?:infrastructure|composition)\//);
  }
});

it('preserves exact canonical bytes and publisher proof verification after extraction', async () => {
  expect(existsSync(root + 'shared/canonical-json.ts')).toBe(true);
  const { canonicalReport } = await import('../packages/core/src/shared/canonical-json');
  const { HmacExecutorAttestor } = await import('../packages/core/src/signing/publisher');
  const report = { z: [true, null, -0, { b: 'Синтетический отчёт', a: '\n"' }], a: 1 };
  const canonical = '{"a":1,"z":[true,null,0,{"a":"\\n\\\"","b":"Синтетический отчёт"}]}';
  expect(canonicalReport(report)).toBe(canonical);
  const key = Buffer.alloc(32, 9);
  const proof = createHmac('sha256', key).update(canonical).digest('hex');
  const attestor = new HmacExecutorAttestor(key);
  expect(await attestor.verify(report as never, proof)).toBe(true);
  expect(await attestor.verify({ ...report, a: 2 } as never, proof)).toBe(false);
  expect(await attestor.verify(report as never, 'A'.repeat(64))).toBe(false);
  for (const value of [undefined, NaN, Infinity, 1n, { invalid: undefined }])
    expect(() => canonicalReport(value)).toThrow('EXECUTOR_REPORT_INVALID');
});
