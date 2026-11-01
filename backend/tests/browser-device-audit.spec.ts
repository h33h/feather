import { expect, test, type Page } from '@playwright/test';
import { installerAccount, installerDevices, mockInstaller } from './helpers/browser-installer';
const pendingDevice = (id: string, name: string, os: string | null = '18.0') => ({
  ...installerDevices.devices[0],
  id,
  name,
  status: 'collected',
  selected: false,
  os_version: os,
});
const identity = {
  id: 'identity',
  name: 'iPhone 16',
  udid: '••••1234',
  product: 'iPhone',
  osVersion: null,
  createdAt: 1,
  verifiedAt: 1,
  status: 'verified',
  bindings: [
    {
      deviceId: 'first',
      connectionId: 'team',
      teamId: 'TEAM123456',
      generation: 1,
      status: 'collected',
      shared: false,
    },
  ],
};
async function profileRoute(page: Page, baseURL: string | undefined, lifetime = 60000) {
  await page.route('**/api/devices/challenge', (route) =>
    route.fulfill({
      json: {
        profileXml: '<plist/>',
        profileUrl: baseURL + '/device-profile/public-transfer',
        qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"/>',
        expiresAt: Date.now() + lifetime,
      },
    }),
  );
  await page.route('**/device-profile/public-transfer', (route) =>
    route.fulfill({ contentType: 'application/x-apple-aspen-config', body: '<plist/>' }),
  );
}

test('registration intent belongs only to the named selected device and team', async ({ page }) => {
  await mockInstaller(page, {
    devices: {
      devices: [pendingDevice('first', 'iPhone 16'), pendingDevice('second', 'iPhone 15')],
      collectedDevices: [],
    },
  });
  const submissions: { path: string; body: unknown }[] = [];
  await page.route('**/api/devices/*/register', (route) => {
    submissions.push({
      path: new URL(route.request().url()).pathname,
      body: route.request().postDataJSON(),
    });
    return route.fulfill({ json: { status: 'apple_processing' } });
  });
  await page.goto('/');
  await expect(page.getByRole('checkbox')).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Зарегистрировать устройство: iPhone 16', exact: true }),
  ).toBeEnabled();
  await page
    .getByRole('combobox', { name: 'Устройство для установки', exact: true })
    .selectOption('second');
  await page
    .getByRole('button', { name: 'Зарегистрировать устройство: iPhone 15', exact: true })
    .click();
  await expect
    .poll(() => submissions)
    .toEqual([{ path: '/api/devices/second/register', body: { slotConsent: true } }]);
});

test('missing iOS input is isolated between selected device bindings', async ({ page }) => {
  await mockInstaller(page, {
    devices: {
      devices: [
        pendingDevice('first', 'iPhone 16', null),
        pendingDevice('second', 'iPhone 15', null),
      ],
      collectedDevices: [],
    },
  });
  const submissions: { path: string; body: unknown }[] = [];
  for (const endpoint of ['os', 'register'])
    await page.route('**/api/devices/*/' + endpoint, (route) => {
      submissions.push({
        path: new URL(route.request().url()).pathname,
        body: route.request().postDataJSON(),
      });
      return route.fulfill({ json: { ok: true } });
    });
  await page.goto('/');
  await page.getByRole('textbox').fill('18.2');
  await page.getByRole('combobox').selectOption('second');
  await expect(page.getByRole('textbox')).toHaveValue('');
  await expect(page.getByRole('button', { name: /Зарегистрировать/ })).toBeDisabled();
  await page.getByRole('textbox').fill('17.7');
  await page.getByRole('button', { name: /Зарегистрировать/ }).click();
  await expect
    .poll(() => submissions)
    .toEqual([
      { path: '/api/devices/second/os', body: { version: '17.7' } },
      { path: '/api/devices/second/register', body: { slotConsent: true } },
    ]);
});

test('rebinding the same device clears its previous iOS input', async ({ page }) => {
  const state = await mockInstaller(page, {
    devices: { devices: [pendingDevice('first', 'iPhone 16', null)], collectedDevices: [] },
  });
  await page.goto('/');
  await page.getByRole('textbox').fill('18.2');
  state.devices = {
    devices: [{ ...pendingDevice('first', 'iPhone 16', null), team_id: 'OTHERTEAM1' }],
    collectedDevices: [],
  };
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.getByRole('textbox')).toHaveValue('');
  await expect(page.getByRole('button', { name: /Зарегистрировать/ })).toBeDisabled();
});

test('rebinding during an iOS save prevents the old registration action', async ({ page }) => {
  const state = await mockInstaller(page, {
    devices: { devices: [pendingDevice('first', 'iPhone 16', null)], collectedDevices: [identity] },
  });
  let entered!: () => void,
    release!: () => void,
    registrations = 0;
  const requested = new Promise<void>((resolve) => (entered = resolve)),
    delayed = new Promise<void>((resolve) => (release = resolve));
  await page.route('**/api/devices/first/os', async (route) => {
    entered();
    await delayed;
    await route.fulfill({ json: { ok: true } });
  });
  await page.route('**/api/devices/first/register', (route) => {
    registrations++;
    return route.fulfill({ json: { status: 'apple_processing' } });
  });
  await page.goto('/');
  await page.getByRole('textbox').fill('18.2');
  await page.getByRole('button', { name: /Зарегистрировать/ }).click();
  await requested;
  let completed!: Promise<unknown>;
  try {
    state.devices = {
      devices: [pendingDevice('first', 'iPhone 16', null)],
      collectedDevices: [{ ...identity, bindings: [{ ...identity.bindings[0], generation: 2 }] }],
    };
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(page.getByRole('textbox')).toHaveValue('');
    completed = page.waitForRequest('**/api/session');
  } finally {
    release();
  }
  await completed;
  expect(registrations).toBe(0);
});

for (const status of ['apple_processing', 'certificate_required', 'ineligible', 'disabled'])
  test('existing ' + status + ' identity keeps collection secondary', async ({ page }) => {
    await mockInstaller(page, {
      devices: {
        devices: [{ ...installerDevices.devices[0], status, selected: false }],
        collectedDevices: [],
      },
    });
    let polls = 0;
    await page.route('**/api/devices/binding-device/poll', (route) => {
      polls++;
      return route.fulfill({ json: { status } });
    });
    await page.goto('/');
    await expect(
      page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }),
    ).toHaveCount(0);
    await page
      .getByRole('button', { name: 'Проверить устройство: iPhone 16', exact: true })
      .click();
    await expect.poll(() => polls).toBe(1);
    await page.getByRole('button', { name: 'Добавить другое устройство', exact: true }).click();
    await expect(
      page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }),
    ).toBeVisible();
  });

test('an unbound identity waits for its binding before offering registration', async ({ page }) => {
  await mockInstaller(page, {
    devices: { devices: [], collectedDevices: [{ ...identity, bindings: [] }] },
  });
  await page.goto('/');
  await expect(page.getByRole('status').filter({ hasText: 'Идентификатор получен' })).toBeVisible();
  await expect(page.getByRole('button', { name: /Зарегистрировать/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Добавить другое устройство', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }),
  ).toBeVisible();
});

test('profile request is explicit and opens a separate QR screen without a modal', async ({
  page,
  baseURL,
  context,
}) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  await profileRoute(page, baseURL);
  let requests = 0;
  page.on('request', (request) => {
    if (request.url().endsWith('/api/devices/challenge')) requests++;
  });
  await page.goto('/');
  expect(requests).toBe(0);
  await expect(
    page.getByText('Продолжите на iPhone, на который установите клиент.', { exact: true }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Продолжите на iPhone', exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: 'Скопировать ссылку', exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
    baseURL + '/device-profile/public-transfer',
  );
});

for (const delay of [0, 31000])
  test(
    'Back cancels profile UI while delayed refresh finishes: ' + delay,
    async ({ page, baseURL }) => {
      if (delay) await page.clock.install();
      await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
      let challenged = false,
        release!: () => void;
      const delayed = new Promise<void>((resolve) => (release = resolve));
      await page.route('**/api/session', async (route) => {
        if (challenged) await delayed;
        return route.fulfill({ json: installerAccount });
      });
      await profileRoute(page, baseURL);
      page.on('request', (request) => {
        if (request.url().endsWith('/api/devices/challenge')) challenged = true;
      });
      await page.goto('/');
      await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
      try {
        await expect(
          page.getByRole('img', { name: 'QR профиля для iPhone', exact: true }),
        ).toBeVisible();
        await page.getByRole('button', { name: 'Назад', exact: true }).click();
        await expect(
          page.getByRole('heading', { name: 'Добавьте iPhone', exact: true }),
        ).toBeVisible();
        if (delay) await page.clock.fastForward(delay);
      } finally {
        release();
      }
      await expect(
        page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }),
      ).toBeEnabled();
      await expect(
        page.getByRole('img', { name: 'QR профиля для iPhone', exact: true }),
      ).toHaveCount(0);
    },
  );

test('browser Forward cannot revive a cancelled profile capability', async ({ page, baseURL }) => {
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  await profileRoute(page, baseURL);
  await page.goto('/');
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'Добавьте iPhone', exact: true })).toBeVisible();
  await page.goForward();
  await expect(page.locator('.installer')).toHaveAttribute('data-view', 'device');
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toHaveCount(
    0,
  );
});

test('back from profile focuses the current step heading', async ({ page, baseURL }) => {
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  await profileRoute(page, baseURL);
  await page.goto('/');
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  await expect(
    page.getByRole('heading', { name: 'Продолжите на iPhone', exact: true }),
  ).toBeFocused();
  await page.getByRole('button', { name: 'Назад', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Добавьте iPhone', exact: true })).toBeFocused();
});

test('delayed profile refresh does not steal focus from the profile menu', async ({
  page,
  baseURL,
}) => {
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  let challenged = false,
    release!: () => void;
  const delayed = new Promise<void>((resolve) => (release = resolve));
  await page.route('**/api/session', async (route) => {
    if (challenged) await delayed;
    return route.fulfill({ json: installerAccount });
  });
  await profileRoute(page, baseURL);
  page.on('request', (request) => {
    if (request.url().endsWith('/api/devices/challenge')) challenged = true;
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  try {
    await expect(
      page.getByRole('heading', { name: 'Продолжите на iPhone', exact: true }),
    ).toBeVisible();
    await page.locator('.installer-profile-trigger').click();
    await page.getByRole('switch', { name: 'Тёмная тема', exact: true }).focus();
  } finally {
    release();
  }
  await expect(page.getByRole('switch', { name: 'Тёмная тема', exact: true })).toBeFocused();
});

test('profile QR stops offering an expired capability', async ({ page, baseURL }) => {
  await page.clock.install();
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  await profileRoute(page, baseURL, 2000);
  await page.goto('/');
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toBeVisible();
  await page.clock.fastForward(3000);
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toHaveCount(
    0,
  );
  await expect(page.getByRole('button', { name: 'Обновить ссылку', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Скопировать ссылку', exact: true })).toHaveCount(
    0,
  );
});

test('a profile response after logout cannot start the previous owner download', async ({
  page,
  baseURL,
}) => {
  await page.addInitScript(() =>
    Object.defineProperty(navigator, 'userAgent', { configurable: true, value: 'iPhone' }),
  );
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  let entered!: () => void, release!: () => void;
  const requested = new Promise<void>((resolve) => (entered = resolve)),
    delayed = new Promise<void>((resolve) => (release = resolve));
  await page.route('**/api/devices/challenge', async (route) => {
    entered();
    await delayed;
    await route.fulfill({
      json: {
        profileXml: '<plist/>',
        profileUrl: baseURL + '/device-profile/public-transfer',
        qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"/>',
        expiresAt: Date.now() + 60000,
      },
    });
  });
  await page.route('**/device-profile/public-transfer', (route) =>
    route.fulfill({ contentType: 'application/x-apple-aspen-config', body: '<plist/>' }),
  );
  await page.goto('/');
  await page.getByRole('button', { name: 'Скачать профиль', exact: true }).click();
  await requested;
  const completed = page.waitForResponse('**/api/devices/challenge');
  let downloaded!: Promise<boolean>;
  try {
    await page.locator('.installer-profile-trigger').click();
    await page.getByRole('button', { name: 'Выйти', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Войти с passkey', exact: true })).toBeVisible();
    downloaded = page.waitForEvent('download', { timeout: 1500 }).then(
      () => true,
      () => false,
    );
  } finally {
    release();
  }
  await completed;
  expect(await downloaded).toBe(false);
});

test('registration obtains the full UDID through the owner-scoped reveal endpoint', async ({
  page,
}) => {
  await mockInstaller(page, {
    devices: {
      devices: [pendingDevice('first', 'iPhone 16')],
      collectedDevices: [{ ...identity, osVersion: '18.0' }],
    },
  });
  await page.route('**/api/devices/collected/identity/udid', (route) =>
    route.fulfill({ json: { id: 'identity', udid: '00008140-001234567890ABCD' } }),
  );
  await page.goto('/');
  await expect(page.getByText('00008140-001234567890ABCD', { exact: true })).toBeVisible();
});

test('collecting a known iPhone again continues after fresh verification of the same identity', async ({
  page,
  baseURL,
}) => {
  const known = {
    ...identity,
    osVersion: '18.0',
    bindings: [{ ...identity.bindings[0], deviceId: 'binding-device', status: 'ready' }],
  };
  const state = await mockInstaller(page, {
    devices: { ...installerDevices, collectedDevices: [known] },
  });
  await profileRoute(page, baseURL);
  await page.goto('/');
  await page.getByRole('button', { name: 'Параметры установки', exact: true }).click();
  await page.getByRole('button', { name: 'Изменить устройство', exact: true }).click();
  await page.getByRole('button', { name: 'Добавить другое устройство', exact: true }).click();
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toBeVisible();
  state.devices = { ...installerDevices, collectedDevices: [{ ...known, verifiedAt: 2 }] };
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeEnabled();
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toHaveCount(
    0,
  );
});
