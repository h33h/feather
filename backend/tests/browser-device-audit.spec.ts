import { expect, test } from '@playwright/test';
import { installerAccount, installerDevices, mockInstaller } from './helpers/browser-installer';

const pendingDevice = (id: string, name: string, osVersion: string | null = '18.0') => ({
  ...installerDevices.devices[0],
  id,
  name,
  status: 'collected',
  selected: false,
  os_version: osVersion,
});

test('slot consent belongs only to the named device and team', async ({ page }) => {
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
  const first = page.locator('.installer-device').filter({ hasText: 'iPhone 16' });
  const second = page.locator('.installer-device').filter({ hasText: 'iPhone 15' });
  await first.getByRole('checkbox').check();
  await expect(second.getByRole('checkbox')).not.toBeChecked();
  await expect(second.getByRole('button', { name: /Зарегистрировать/ })).toBeDisabled();
  await expect(first.getByRole('checkbox')).toHaveAccessibleName(/iPhone 16.*TEAM123456/);
  await first.getByRole('button', { name: /Зарегистрировать/ }).click();
  await expect
    .poll(() => submissions)
    .toEqual([{ path: '/api/devices/first/register', body: { slotConsent: true } }]);
  await expect(first.getByRole('checkbox')).not.toBeChecked();
});

test('missing iOS versions are collected separately for each device binding', async ({ page }) => {
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
  await page.route('**/api/devices/*/os', (route) => {
    submissions.push({
      path: new URL(route.request().url()).pathname,
      body: route.request().postDataJSON(),
    });
    return route.fulfill({ json: { ok: true } });
  });
  await page.route('**/api/devices/*/register', (route) => {
    submissions.push({
      path: new URL(route.request().url()).pathname,
      body: route.request().postDataJSON(),
    });
    return route.fulfill({ json: { status: 'apple_processing' } });
  });
  await page.goto('/');
  const first = page.locator('.installer-device').filter({ hasText: 'iPhone 16' });
  const second = page.locator('.installer-device').filter({ hasText: 'iPhone 15' });
  await first.getByRole('textbox').fill('18.2');
  await expect(second.getByRole('textbox')).toHaveValue('');
  await second.getByRole('checkbox').check();
  await expect(second.getByRole('button', { name: /Зарегистрировать/ })).toBeDisabled();
  await second.getByRole('textbox').fill('17.7');
  await second.getByRole('button', { name: /Зарегистрировать/ }).click();
  await expect
    .poll(() => submissions)
    .toEqual([
      { path: '/api/devices/second/os', body: { version: '17.7' } },
      { path: '/api/devices/second/register', body: { slotConsent: true } },
    ]);
});

test('rebinding the same device to another Apple team clears slot consent and iOS input', async ({
  page,
}) => {
  const state = await mockInstaller(page, {
    devices: { devices: [pendingDevice('first', 'iPhone 16', null)], collectedDevices: [] },
  });
  await page.goto('/');
  await page.getByRole('checkbox').check();
  await page.getByRole('textbox').fill('18.2');
  state.devices = {
    devices: [{ ...pendingDevice('first', 'iPhone 16', null), team_id: 'OTHERTEAM1' }],
    collectedDevices: [],
  };
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.getByRole('checkbox')).not.toBeChecked();
  await expect(page.getByRole('textbox')).toHaveValue('');
  await expect(page.getByRole('checkbox')).toHaveAccessibleName(/OTHERTEAM1/);
});

test('rebinding during an iOS save cancels the previous generation registration consent', async ({
  page,
}) => {
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
  const state = await mockInstaller(page, {
    devices: { devices: [pendingDevice('first', 'iPhone 16', null)], collectedDevices: [identity] },
  });
  let entered!: () => void,
    release!: () => void,
    registrations = 0;
  const requested = new Promise<void>((resolve) => (entered = resolve));
  const delayed = new Promise<void>((resolve) => (release = resolve));
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
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: /Зарегистрировать/ }).click();
  await requested;
  let completed!: Promise<unknown>;
  try {
    state.devices = {
      devices: [pendingDevice('first', 'iPhone 16', null)],
      collectedDevices: [{ ...identity, bindings: [{ ...identity.bindings[0], generation: 2 }] }],
    };
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(page.getByRole('checkbox')).not.toBeChecked();
    completed = page.waitForRequest('**/api/session');
  } finally {
    release();
  }
  await completed;
  expect(registrations).toBe(0);
});

for (const status of ['apple_processing', 'certificate_required', 'ineligible', 'disabled']) {
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
    ).toBeHidden();
    const device = page.locator('.installer-device').filter({ hasText: 'iPhone 16' });
    await expect(device.getByRole('button', { name: /Проверить.*iPhone 16/ })).toBeVisible();
    await device.getByRole('button', { name: /Проверить.*iPhone 16/ }).click();
    await expect.poll(() => polls).toBe(1);
    await page.getByText('Добавить другое устройство', { exact: true }).click();
    await expect(
      page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }),
    ).toBeVisible();
  });
}

test('an unbound collected identity also keeps initial collection secondary', async ({ page }) => {
  await mockInstaller(page, {
    devices: {
      devices: [],
      collectedDevices: [
        {
          id: 'identity',
          name: 'iPhone 16',
          udid: '••••1234',
          product: 'iPhone',
          osVersion: '18.0',
          createdAt: 1,
          verifiedAt: 1,
          status: 'verified',
          bindings: [],
        },
      ],
    },
  });
  await page.goto('/');
  await expect(page.getByRole('status').filter({ hasText: 'Идентификатор получен' })).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }),
  ).toBeHidden();
  await page.getByText('Добавить другое устройство', { exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }),
  ).toBeVisible();
});

test('before profile collection the user sees the data, destination and separate Apple action', async ({
  page,
  baseURL,
}) => {
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  let challenges = 0;
  await page.route('**/api/devices/challenge', (route) => {
    challenges++;
    return route.fulfill({
      json: {
        profileXml: '<plist/>',
        profileUrl: baseURL + '/device-profile/public-transfer',
        qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"/>',
        expiresAt: Date.now() + 60000,
      },
    });
  });
  await page.goto('/');
  const purpose = page.locator('.device-profile').getByText(/UDID, модель и версию системы/);
  await expect(purpose).toBeVisible();
  await expect(purpose).toContainText(baseURL!);
  await expect(page.locator('.device-profile')).toContainText(/не управляет устройством.*MDM/i);
  await expect(page.locator('.device-profile')).toContainText(/Регистрация.*Apple.*отдельн/i);
  expect(challenges).toBe(0);
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  await expect(page.getByLabel('Ссылка для iPhone', { exact: true })).toHaveValue(
    baseURL + '/device-profile/public-transfer',
  );
  await expect(
    page.getByRole('button', { name: 'Скопировать ссылку для iPhone', exact: true }),
  ).toBeVisible();
});

for (const { openerName, delay } of [
  { openerName: 'Продолжить на iPhone', delay: 0 },
  { openerName: 'Скачать профиль для UDID', delay: 0 },
  { openerName: 'Продолжить на iPhone', delay: 31000 },
]) {
  test(
    'Escape restores the exact keyboard opener after delayed profile refresh: ' +
      openerName +
      (delay ? ' after a long request' : ''),
    async ({ page, baseURL }) => {
      if (delay) await page.clock.install();
      await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
      let challenged = false;
      let release!: () => void;
      const delayed = new Promise<void>((resolve) => (release = resolve));
      await page.route('**/api/session', async (route) => {
        if (challenged) await delayed;
        return route.fulfill({ json: installerAccount });
      });
      await page.route('**/api/devices/challenge', (route) => {
        challenged = true;
        return route.fulfill({
          json: {
            profileXml: '<plist/>',
            profileUrl: baseURL + '/device-profile/public-transfer',
            qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"/>',
            expiresAt: Date.now() + 60000,
          },
        });
      });
      await page.goto('/');
      const opener = page.getByRole('button', { name: openerName, exact: true });
      await opener.focus();
      await page.keyboard.press('Enter');
      try {
        await expect(page.getByRole('dialog')).toBeVisible();
        await page.keyboard.press('Escape');
        await expect(page.getByRole('dialog')).toHaveCount(0);
        await expect(opener).toBeDisabled();
        if (delay) await page.clock.fastForward(delay);
      } finally {
        release();
      }
      await expect(opener).toBeEnabled();
      await expect(opener).toBeFocused();
    },
  );
}

test('a disconnected profile opener returns keyboard focus to the current step heading', async ({
  page,
  baseURL,
}) => {
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  await page.route('**/api/devices/challenge', (route) =>
    route.fulfill({
      json: {
        profileXml: '<plist/>',
        profileUrl: baseURL + '/device-profile/public-transfer',
        qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"/>',
        expiresAt: Date.now() + 60000,
      },
    }),
  );
  await page.goto('/');
  const opener = page.getByRole('button', { name: 'Продолжить на iPhone', exact: true });
  await opener.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog')).toBeVisible();
  await opener.evaluate((element) => element.remove());
  await page.keyboard.press('Escape');
  await expect(page.getByRole('heading', { name: 'Добавьте iPhone', exact: true })).toBeFocused();
});

test('delayed profile completion cannot steal focus from another chosen control', async ({
  page,
  baseURL,
}) => {
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  let challenged = false;
  let release!: () => void;
  const delayed = new Promise<void>((resolve) => (release = resolve));
  await page.route('**/api/session', async (route) => {
    if (challenged) await delayed;
    return route.fulfill({ json: installerAccount });
  });
  await page.route('**/api/devices/challenge', (route) => {
    challenged = true;
    return route.fulfill({
      json: {
        profileXml: '<plist/>',
        profileUrl: baseURL + '/device-profile/public-transfer',
        qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"/>',
        expiresAt: Date.now() + 60000,
      },
    });
  });
  await page.goto('/');
  const opener = page.getByRole('button', { name: 'Продолжить на iPhone', exact: true });
  await opener.focus();
  await page.keyboard.press('Enter');
  const theme = page.getByRole('combobox', { name: 'Цветовая тема', exact: true });
  try {
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await theme.focus();
  } finally {
    release();
  }
  await expect(opener).toBeEnabled();
  await expect(theme).toBeFocused();
});

test('profile QR stops offering an expired capability', async ({ page, baseURL }) => {
  await page.clock.install();
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  await page.route('**/api/devices/challenge', (route) =>
    route.fulfill({
      json: {
        profileXml: '<plist/>',
        profileUrl: baseURL + '/device-profile/public-transfer',
        qrSvg: '<svg xmlns="http://www.w3.org/2000/svg"/>',
        expiresAt: Date.now() + 2000,
      },
    }),
  );
  await page.goto('/');
  await page.getByRole('button', { name: 'Продолжить на iPhone', exact: true }).click();
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toBeVisible();
  await page.clock.fastForward(3000);
  await expect(page.getByRole('img', { name: 'QR профиля для iPhone', exact: true })).toHaveCount(
    0,
  );
  await expect(page.getByLabel('Ссылка для iPhone', { exact: true })).toHaveCount(0);
  await expect(
    page.getByRole('button', { name: 'Получить новую ссылку', exact: true }),
  ).toBeVisible();
});

test('a profile response after logout cannot start a download for the previous owner', async ({
  page,
  baseURL,
}) => {
  await mockInstaller(page, { devices: { devices: [], collectedDevices: [] } });
  let entered!: () => void, release!: () => void;
  const requested = new Promise<void>((resolve) => (entered = resolve));
  const delayed = new Promise<void>((resolve) => (release = resolve));
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
  await page.route('**/device-profile/public-transfer', (route) => {
    return route.fulfill({ contentType: 'application/x-apple-aspen-config', body: '<plist/>' });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Скачать профиль для UDID', exact: true }).click();
  await requested;
  const completed = page.waitForResponse('**/api/devices/challenge');
  let downloaded!: Promise<boolean>;
  try {
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
  await expect(page.getByRole('dialog')).toHaveCount(0);
});
