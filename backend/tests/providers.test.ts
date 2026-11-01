import { loginFixture, connectionFixture } from './helpers/login';
import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { MappingService } from '../packages/core/src/signing/mapping';
import { AppleClient } from '../packages/core/src/infrastructure/apple-api';
import { Service } from '../packages/core/src/application/service';
it('never blindly repeats a timed-out mutation and retries reads within budget', async () => {
  let calls = 0;
  const client = new AppleClient(
    async () => 'synthetic-jwt',
    async () => {
      calls++;
      throw new Error('synthetic transport failure');
    },
    async () => {},
  );
  await expect(client.request('POST', '/v1/certificates', {})).rejects.toThrow(
    'MUTATION_OUTCOME_UNKNOWN',
  );
  expect(calls).toBe(1);
  calls = 0;
  await expect(client.request('GET', '/v1/devices')).rejects.toThrow('APPLE_TEMPORARY_UNAVAILABLE');
  expect(calls).toBe(3);
});
