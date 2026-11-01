import { expect, it } from 'vitest';
import { diagnosticError } from '../packages/core/src/signing/diagnostics';

it('redacts credentials and limits cyclic error causes without losing network codes', () => {
  const error = Object.assign(
    new Error('Bearer secret-value https://user:pass@example.com/file?token=private'),
    { code: 'ECONNRESET', cause: undefined as unknown },
  );
  error.cause = error;
  const result = diagnosticError(error, { ISIGN_RUNNER_TOKEN: 'secret-value' });
  const serialized = JSON.stringify(result);
  expect(result).toMatchObject({ name: 'Error', code: 'ECONNRESET' });
  for (const secret of ['secret-value', 'user:pass', 'token=private'])
    expect(serialized).not.toContain(secret);
  expect(serialized).toContain('example.com');
  expect(serialized.length).toBeLessThan(16000);
});

it('does not serialize arbitrary thrown objects containing secrets', () => {
  expect(JSON.stringify(diagnosticError({ password: 'private' }))).not.toContain('private');
});
