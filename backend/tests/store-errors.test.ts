import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { EXPECTED_RUNNER_FAILURE_CODES } from '../packages/core/src/infrastructure/runner-http';
import { messages } from '../../web/src/shared/api/errors';

it('explains every public IPA failure and runner capacity error', () => {
  for (const code of [...EXPECTED_RUNNER_FAILURE_CODES, 'RUNNER_BUSY']) {
    expect(messages[code], code).toBeTruthy();
    expect(messages[code], code).not.toContain('UND_ERR');
  }
});

it('keeps the web protocol allowlist equal to the guest protocol allowlist', () => {
  const python = readFileSync(
    new URL('../packages/runner/protocol/errors.py', import.meta.url),
    'utf8',
  );
  const codes = [
    ...python.split('class ExpectedGuestFailure')[0].matchAll(/"([A-Z][A-Z_]+)"/g),
  ].map((match) => match[1]);
  expect([...EXPECTED_RUNNER_FAILURE_CODES].sort()).toEqual(codes.sort());
});
