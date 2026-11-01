import { expect, it } from 'vitest';
import {
  appleSchema,
  devicesSchema,
  librarySchema,
  sessionSchema,
} from '../packages/contracts/src/index';
import { query } from '../../web/src/shared/api/query';
import { installerAccount, installerApple, installerDevices } from './helpers/browser-installer';
it('typed queries validate and project nested DTOs before returning them', async () => {
  const response = await query(
    async () => ({ ...installerAccount, session_hash: 'secret' }),
    'session',
    sessionSchema,
  );
  expect(response).toEqual({
    authenticated: true,
    csrf: installerAccount.csrf,
    profile: installerAccount.profile,
    capabilities: installerAccount.capabilities,
  });
  await expect(
    query(async () => ({ jobs: [], artifacts: [{ id: 'a' }] }), 'library', librarySchema),
  ).rejects.toThrow();
});
it('installer fixtures satisfy the actual account and device DTOs', () => {
  expect(sessionSchema.parse(installerAccount)).toBeDefined();
  expect(appleSchema.parse(installerApple)).toBeDefined();
  expect(devicesSchema.parse(installerDevices)).toBeDefined();
});
it('installer DTO validation catches incomplete device rows', () => {
  expect(() => devicesSchema.parse({ devices: [{ id: 'd' }], collectedDevices: [] })).toThrow();
});
it('checked admin data failures carry safe display copy and retain schema diagnostics as cause', async () => {
  const { adminUsersSchema } = await import('../packages/contracts/src/index');
  const { z } = await import('zod');
  const failure = await query(
    async () => ({ users: [{ loginName: 123 }] }),
    'admin/users',
    adminUsersSchema,
  ).catch((error: unknown) => error);
  expect(failure).toMatchObject({
    message: 'Не удалось загрузить данные. Повторите попытку.',
    cause: expect.any(z.ZodError),
  });
  expect(String(failure)).not.toMatch(/invalid_type|loginName|expected|issues/);
});
