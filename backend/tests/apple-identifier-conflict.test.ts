import { expect, it } from 'vitest';
import { AppleClient } from '../packages/core/src/infrastructure/apple-api';
it('distinguishes a confirmed identifier conflict from permission and provider failures', async () => {
  const payload = {
    errors: [
      {
        code: 'ENTITY_ERROR.ATTRIBUTE.INVALID',
        source: { pointer: '/data/attributes/identifier' },
        detail: 'The bundle identifier is not available.',
      },
    ],
  };
  const conflict = new AppleClient(
    async () => 'jwt',
    async () => ({ status: 409, data: payload }),
  );
  await expect(conflict.request('POST', '/v1/bundleIds', {})).rejects.toThrow(
    'BUNDLE_IDENTIFIER_UNAVAILABLE',
  );
  const denied = new AppleClient(
    async () => 'jwt',
    async () => ({ status: 403, data: payload }),
  );
  await expect(denied.request('POST', '/v1/bundleIds', {})).rejects.toThrow(
    'APPLE_ACCESS_ACTION_REQUIRED',
  );
  const unrelated = new AppleClient(
    async () => 'jwt',
    async () => ({
      status: 409,
      data: { errors: [{ ...payload.errors[0], source: { pointer: '/data/attributes/name' } }] },
    }),
  );
  await expect(unrelated.request('POST', '/v1/bundleIds', {})).rejects.toThrow(
    'APPLE_OPERATION_REJECTED',
  );
});
