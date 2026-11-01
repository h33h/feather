import { expect, it } from 'vitest';
import { loadProviderConfig } from '../packages/core/src/infrastructure/config';
const env = {
  NODE_ENV: 'development',
  ISIGN_ORIGIN: 'http://localhost:3000',
  DATABASE_URL: 'postgres://isign:test-only@127.0.0.1:5432/isign_local',
  ISIGN_PERSONAL_DATABASE_TRANSPORT: 'loopback',
  ISIGN_PERSONAL_DATA: '/tmp/isign-test/data',
  ISIGN_PERSONAL_KEY_FILE: '/tmp/isign-test/key',
  ISIGN_RUNNER_ORIGIN: 'https://runner.internal',
  ISIGN_RUNNER_TOKEN: 'a'.repeat(43),
  ISIGN_RUNNER_AUDIENCE: 'isign-personal',
};
it('uses the same personal product for a loopback development deployment', () => {
  expect(loadProviderConfig(env)).toMatchObject({
    mode: 'personal',
    origin: 'http://localhost:3000',
    databaseTransport: 'loopback',
  });
});
it('rejects public plaintext origins and nonloopback unencrypted databases', () => {
  expect(() =>
    loadProviderConfig({ ...env, ISIGN_ORIGIN: 'http://public.example.test' }),
  ).toThrow();
  expect(() =>
    loadProviderConfig({
      ...env,
      DATABASE_URL: 'postgres://isign:test-only@remote.example.test/isign',
    }),
  ).toThrow();
});
it('rejects an IP address as a passkey relying party before startup', async () => {
  expect(() => loadProviderConfig({ ...env, ISIGN_ORIGIN: 'https://127.0.0.1:3000' })).toThrow(
    'PASSKEY_ORIGIN_DOMAIN_REQUIRED',
  );
  const { PersonalAuth } = await import('../packages/core/src/auth/passkeys');
  expect(() => new PersonalAuth({} as never, 'https://127.0.0.1:3000')).toThrow(
    'PASSKEY_ORIGIN_DOMAIN_REQUIRED',
  );
});
