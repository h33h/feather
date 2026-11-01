import type { Page } from '@playwright/test';
import { appleSchema, devicesSchema, sessionSchema } from '../../packages/contracts/src';

export const installerAccount = {
  authenticated: true,
  csrf: 'synthetic',
  profile: { id: 'owner', loginName: 'owner', role: 'user', publicProfileId: 'profile-public' },
  capabilities: { appleOnboarding: true, bootstrap: true, deviceEnrollment: true, runner: true },
};
export const installerApple = {
  connection: {
    id: 'team',
    state: 'ready',
    team_id: 'TEAM123456',
    identityReady: true,
    shared: false,
  },
  shares: [],
  uploadAllowed: true,
};
export const installerDevices = {
  devices: [
    {
      id: 'binding-device',
      name: 'iPhone 16',
      status: 'ready',
      selected: true,
      os_version: '18.0',
      team_id: 'TEAM123456',
    },
  ],
  collectedDevices: [],
};
export async function mockInstaller(
  page: Page,
  options: { authenticated?: boolean; apple?: unknown; devices?: unknown; release?: boolean } = {},
) {
  const state = {
    authenticated: options.authenticated ?? true,
    apple: options.apple ?? structuredClone(installerApple),
    devices: options.devices ?? structuredClone(installerDevices),
  };
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/client/release')
      return route.fulfill({
        json: { name: 'iSign Client', available: options.release ?? true, version: '2.9.0' },
      });
    if (path === '/api/session')
      return state.authenticated
        ? route.fulfill({ json: sessionSchema.parse(installerAccount) })
        : route.fulfill({ status: 401, json: { code: 'UNAUTHENTICATED' } });
    if (path === '/api/apple') return route.fulfill({ json: appleSchema.parse(state.apple) });
    if (path === '/api/devices') return route.fulfill({ json: devicesSchema.parse(state.devices) });
    if (path === '/api/auth/logout') {
      state.authenticated = false;
      return route.fulfill({ json: { ok: true } });
    }
    return route.fulfill({ status: 404, json: { code: 'NOT_FOUND' } });
  });
  return state;
}
