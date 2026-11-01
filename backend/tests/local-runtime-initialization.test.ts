import { expect, it } from 'vitest';
import { loadProviderConfig } from '../packages/core/src/infrastructure/config';
it('refuses retired runtimes rather than silently creating an embedded database', () => {
  expect(() => loadProviderConfig({ ISIGN_RUNTIME: 'local' })).toThrow('PERSONAL_RUNTIME_REQUIRED');
  expect(() => loadProviderConfig({ ISIGN_RUNTIME: 'production' })).toThrow(
    'PERSONAL_RUNTIME_REQUIRED',
  );
});
