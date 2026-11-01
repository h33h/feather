import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Exercise decryption during image construction, catching ABI/library failures
// before deployment. The fixture contains one synthetic update encrypted by the
// publisher tool, rather than a cached decoded catalog.
const binary = fileURLToPath(new URL('../.tools/isignkit', import.meta.url));
const input = readFileSync(
  new URL('../tests/fixtures/iapps-updated-encrypted.json', import.meta.url),
);
const output = execFileSync(binary, ['gbox', 'decrypt', '-', '--raw', '--gbox-version', '5.6.6'], {
  input,
  encoding: 'utf8',
  timeout: 20000,
  killSignal: 'SIGKILL',
  maxBuffer: 16 * 1024 ** 2,
  env: { PATH: process.env.PATH, LANG: 'C', TZ: 'UTC' },
});
const payload = JSON.parse(output);
assert.equal(payload.length, 1);
assert.equal(payload[0].AO4, 'Synthetic iApps refresh');
assert.equal(payload[0].AO5, '2.0');
assert.equal(payload[0].AO7, 'https://storage.iapps.rejail.ru/s/synthetic/download/synthetic.ipa');
console.log('Verified isignkit decrypts an updated publisher feed');
