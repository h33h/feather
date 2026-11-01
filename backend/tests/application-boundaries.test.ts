import type { HttpApplication } from '../server/http/application';
import { expect, expectTypeOf, it } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

it('keeps database, storage and service construction out of HTTP', () => {
  const directory = 'backend/server/http';
  for (const name of readdirSync(directory).filter((name) => name.endsWith('.ts'))) {
    const source = readFileSync(join(directory, name), 'utf8');
    expect(source, name).not.toMatch(
      /app\.(?:db|storage|artifacts)\b|new (?:JobRequests|InstallationHistory|RunnerAuthorization|ProfileDiagnostics)\b/,
    );
  }
});

it('composition only wires application scenarios and contains no SQL', () => {
  expect(readFileSync('backend/server/composition.ts', 'utf8')).not.toMatch(
    /\b(?:SELECT|UPDATE|INSERT|DELETE)\b/,
  );
});

it('types the HTTP capability surface without database, storage, vault or nested Service.db', () => {
  expectTypeOf<HttpApplication>().not.toHaveProperty('db');
  expectTypeOf<HttpApplication>().not.toHaveProperty('storage');
  expectTypeOf<HttpApplication>().not.toHaveProperty('vault');
  expectTypeOf<HttpApplication['service']>().not.toHaveProperty('db');
  expectTypeOf<HttpApplication['auth']>().not.toHaveProperty('db');
  expectTypeOf<HttpApplication['jobs']>().not.toHaveProperty('queue');
});
