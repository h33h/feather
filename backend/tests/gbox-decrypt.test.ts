import { afterEach, expect, it, vi } from 'vitest';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { decryptGBoxPayload } from '../packages/core/src/catalog/gbox-decrypt';

const directories: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
});
async function tool(code: string) {
  const directory = await mkdtemp(path.join(tmpdir(), 'isign decoder '));
  directories.push(directory);
  const binary = path.join(directory, 'decoder');
  await writeFile(binary, `#!${process.execPath}\n${code}`, { mode: 0o755 });
  return binary;
}

it('passes only stdin and raw decode arguments without application credentials or a shell', async () => {
  vi.stubEnv('ISIGN_TEST_SECRET', 'synthetic-secret');
  const binary = await tool(`
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => input += chunk);
    process.stdin.on('end', () => {
      const args = process.argv.slice(2);
      if (JSON.stringify(args) !== JSON.stringify(['gbox','decrypt','-','--raw','--gbox-version','5.6.6']) ||
          input !== 'publisher bytes; $(exit 1)' || process.env.ISIGN_TEST_SECRET) process.exit(1);
      process.stdout.write(JSON.stringify([
        { AO1: 'SELF_SIGN', AO4: 'Fresh app', AO5: '2.0', AO7: 'https://storage.iapps.rejail.ru/fresh.ipa' },
        { AO1: 'LINK', AO4: 'Instructions', AO5: '', AO7: 'https://example.invalid/not-an-ipa' }
      ]));
    });
  `);
  const decoded = await decryptGBoxPayload(Buffer.from('publisher bytes; $(exit 1)'), binary);
  expect(decoded).toEqual([
    {
      appName: 'Fresh app',
      appVersion: '2.0',
      appImage: undefined,
      appPackage: 'https://storage.iapps.rejail.ru/fresh.ipa',
      appDescription: undefined,
    },
    {
      appName: 'Instructions',
      appVersion: '',
      appImage: undefined,
      appPackage: undefined,
      appDescription: undefined,
    },
  ]);
});

it('reports an unavailable decoder instead of supplying stale data', async () => {
  await expect(
    decryptGBoxPayload(Buffer.from('{}'), path.join(tmpdir(), 'missing-isignkit', 'binary')),
  ).rejects.toThrow('GBOX_DECODER_UNAVAILABLE');
});

it('masks decoder diagnostics and safely handles an early exit while writing stdin', async () => {
  const binary = await tool("process.stderr.write('sensitive upstream content'); process.exit(1);");
  await expect(decryptGBoxPayload(Buffer.alloc(8 * 1024 ** 2), binary)).rejects.toThrow(
    /^GBOX_DECRYPT_FAILED$/,
  );
});

it('refuses malformed decoder output and unsupported raw record types', async () => {
  for (const output of ['not json', '{}', '[{"AO1":"UNKNOWN","AO4":"App","AO5":"1"}]']) {
    const binary = await tool(`process.stdout.write(${JSON.stringify(output)});`);
    await expect(decryptGBoxPayload(Buffer.from('{}'), binary)).rejects.toThrow(
      'UNSUPPORTED_GBOX_SCHEMA',
    );
  }
});

it('bounds decoder output rather than accepting an oversized payload', async () => {
  const binary = await tool("process.stdout.write('x'.repeat(17 * 1024 ** 2));");
  await expect(decryptGBoxPayload(Buffer.from('{}'), binary)).rejects.toThrow(
    'GBOX_DECRYPT_FAILED',
  );
});
