import { expect, test } from '@playwright/test';
import { installerApple, installerDevices, mockInstaller } from './helpers/browser-installer';

test('public site only offers installation and passkey invitation sign-in', async ({ page }) => {
  await mockInstaller(page, { authenticated: false });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'iSign', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Войти с passkey', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Каталог', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Мои приложения', exact: true })).toHaveCount(0);
  await expect(page.locator('input[accept=".ipa"]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Есть приглашение', exact: true }).click();
  await expect(page.getByLabel('Код приглашения', { exact: true })).toBeVisible();
});

test('own Apple key is submitted only to account setup then account preparation continues', async ({
  page,
}) => {
  const state = await mockInstaller(page, {
    apple: { connection: null, shares: [], uploadAllowed: false },
    devices: { devices: [], collectedDevices: [] },
  });
  let input: Record<string, unknown> = {};
  await page.route('**/api/apple/connect', (route) => {
    input = route.request().postDataJSON();
    state.apple = {
      connection: {
        ...installerApple.connection,
        state: 'action_required',
        identityReady: false,
        last_error: 'TEAM_PROOF_REQUIRED',
      },
      shares: [],
      uploadAllowed: false,
    };
    return route.fulfill({ json: { state: 'action_required' } });
  });
  await page.route('**/api/apple/bootstrap', (route) => {
    state.apple = structuredClone(installerApple);
    return route.fulfill({ json: { state: 'ready' } });
  });
  await page.goto('/');
  await page.getByLabel('Issuer ID', { exact: true }).fill('12345678-1234-1234-1234-123456789abc');
  await page.getByLabel('Key ID', { exact: true }).fill('ABC123DEF4');
  await page.getByLabel('Ключ .p8', { exact: true }).setInputFiles({
    name: 'AuthKey_ABC123DEF4.p8',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('synthetic-only-p8'),
  });
  await page.getByRole('button', { name: 'Подключить', exact: true }).click();
  await expect
    .poll(() => input)
    .toMatchObject({
      issuerId: '12345678-1234-1234-1234-123456789abc',
      keyId: 'ABC123DEF4',
      p8: 'synthetic-only-p8',
      keyType: 'team',
    });
  await page.getByRole('button', { name: 'Подготовить аккаунт', exact: true }).click();
  await expect(page.getByText('TEAM123456', { exact: false }).first()).toBeVisible();
});

test('receiving access uses the menu ID and continues after the owner grants it', async ({
  page,
}) => {
  const state = await mockInstaller(page, {
    apple: { connection: null, shares: [], uploadAllowed: false },
    devices: { devices: [], collectedDevices: [] },
  });
  await page.goto('/');
  await page.locator('.installer-profile-trigger').click();
  await expect(page.locator('[data-profile-id]')).toHaveText('profile-public');
  state.apple = { ...installerApple, connection: { ...installerApple.connection, shared: true } };
  await page.keyboard.press('Escape');
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.getByRole('heading', { name: 'Добавьте iPhone', exact: true })).toBeVisible();
});

test('registers collected device using its Apple binding, with explicit slot consent', async ({
  page,
}) => {
  const state = await mockInstaller(page, {
    devices: {
      devices: [{ ...installerDevices.devices[0], status: 'collected', selected: false }],
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
          bindings: [
            {
              deviceId: 'binding-device',
              connectionId: 'team',
              teamId: 'TEAM123456',
              generation: 1,
              status: 'collected',
              shared: false,
            },
          ],
        },
      ],
    },
  });
  let registered = false;
  await page.route('**/api/devices/binding-device/register', (route) => {
    expect(route.request().postDataJSON()).toEqual({ slotConsent: true });
    registered = true;
    state.devices = structuredClone(installerDevices);
    return route.fulfill({ json: { state: 'ready' } });
  });
  await page.goto('/');
  await page
    .getByRole('button', { name: 'Зарегистрировать устройство: iPhone 16', exact: true })
    .click();
  await expect.poll(() => registered).toBe(true);
  await expect(page.getByRole('heading', { name: 'iSign Client', exact: true })).toBeFocused();
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeEnabled();
});

test('installs only fixed client for selected device and obtains an operation-scoped ticket', async ({
  page,
  baseURL,
}) => {
  await mockInstaller(page);
  await page.route('**/api/client/install', (route) => {
    const body = route.request().postDataJSON();
    expect(Object.keys(body).sort()).toEqual(['deviceId', 'key']);
    expect(body.deviceId).toBe('binding-device');
    return route.fulfill({
      json: { operationId: 'install-one', jobId: 'job-one', state: 'queued' },
    });
  });
  await page.route('**/api/client/install/install-one', (route) =>
    route.fulfill({
      json: {
        operationId: 'install-one',
        jobId: 'job-one',
        state: 'ready',
        artifactId: 'artifact',
      },
    }),
  );
  await page.route('**/api/client/install/install-one/ticket', (route) =>
    route.fulfill({
      json: {
        installUrl:
          'itms-services://?action=download-manifest&url=' +
          encodeURIComponent(baseURL + '/install/cap/manifest.plist'),
        handoffUrl: baseURL + '/handoff/cap',
        qrSvg:
          '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24"><path d="M0 0h24v24H0z"/></svg>',
        expiresAt: Date.now() + 60000,
      },
    }),
  );
  await page.goto('/');
  await page.getByRole('button', { name: 'Подготовить установку', exact: true }).click();
  await page.getByRole('button', { name: 'Установить', exact: true }).click();
  await expect(
    page.getByRole('img', { name: 'QR установки iSign Client', exact: true }),
  ).toBeVisible();
});

test('unpublished client release is truthful and does not start a signing request', async ({
  page,
}) => {
  await mockInstaller(page, { release: false });
  await page.goto('/');
  await expect(
    page.getByText('Версия клиента ещё не опубликована.', { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeDisabled();
});

test('installer is usable on a phone and has no management navigation', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockInstaller(page);
  await page.goto('/');
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '/tmp/isign-installer-mobile.png', fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.screenshot({ path: '/tmp/isign-installer-desktop.png', fullPage: true });
});

test('web administration route is removed', async ({ page }) => {
  await mockInstaller(page);
  const response = await page.goto('/admin');
  expect(response?.status()).toBe(404);
});

test('reload resumes the same installation without resubmitting source', async ({ page }) => {
  await mockInstaller(page);
  let submissions = 0,
    ready = false;
  await page.route('**/api/client/install', (route) => {
    submissions++;
    return route.fulfill({ json: { operationId: 'recover', jobId: 'job', state: 'queued' } });
  });
  await page.route('**/api/client/install/recover', (route) =>
    route.fulfill({
      json: {
        operationId: 'recover',
        jobId: 'job',
        state: ready ? 'ready' : 'queued',
        ...(ready ? { artifactId: 'artifact' } : {}),
      },
    }),
  );
  await page.goto('/');
  await page.getByRole('button', { name: 'Подготовить установку', exact: true }).click();
  await expect(page.getByText('Ожидаем очередь на подпись', { exact: true })).toBeVisible();
  ready = true;
  await page.reload();
  await expect(page.getByRole('button', { name: 'Установить', exact: true })).toBeVisible();
  expect(submissions).toBe(1);
});

test('logout fences a late signing submission and clears its browser recovery record', async ({
  page,
}) => {
  await mockInstaller(page);
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => (release = resolve)),
    requested = new Promise<void>((resolve) => (entered = resolve));
  await page.route('**/api/client/install', async (route) => {
    entered();
    await pending;
    await route.fulfill({
      json: { operationId: 'late', jobId: 'job', state: 'ready', artifactId: 'artifact' },
    });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Подготовить установку', exact: true }).click();
  await requested;
  await page.locator('.installer-profile-trigger').click();
  await page.getByRole('button', { name: 'Выйти', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Войти с passkey', exact: true })).toBeVisible();
  try {
    await expect(page.getByRole('button', { name: 'Войти с passkey', exact: true })).toBeEnabled();
  } finally {
    release();
  }
  await expect(page.getByRole('button', { name: 'Установить', exact: true })).toHaveCount(0);
  expect(
    await page.evaluate(() => sessionStorage.getItem('isign-client-install:owner')),
  ).toBeNull();
});

test('malformed browser recovery state does not prevent installation', async ({ page }) => {
  await page.addInitScript(() => sessionStorage.setItem('isign-client-install:owner', 'null'));
  await mockInstaller(page);
  await page.goto('/');
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeEnabled();
});

test('theme choice works in the installer and survives reload', async ({ page }) => {
  await mockInstaller(page);
  await page.goto('/');
  await page.locator('.installer-profile-trigger').click();
  await page.getByRole('switch', { name: 'Тёмная тема', exact: true }).check();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

for (const status of ['apple_processing', 'certificate_required', 'ineligible', 'disabled']) {
  test('keeps an existing device visible with recovery action: ' + status, async ({ page }) => {
    await mockInstaller(page, {
      devices: {
        devices: [{ ...installerDevices.devices[0], status, selected: false }],
        collectedDevices: [],
      },
    });
    await page.goto('/');
    await expect(page.getByText('iPhone 16', { exact: true })).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Проверить устройство: iPhone 16', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Подготовить установку', exact: true }),
    ).toHaveCount(0);
  });
}

test('expired ready artifact can be prepared again after ticket refusal', async ({ page }) => {
  await page.addInitScript(() =>
    sessionStorage.setItem(
      'isign-client-install:owner',
      JSON.stringify({ key: 'one', deviceId: 'binding-device', operationId: 'expired' }),
    ),
  );
  await mockInstaller(page);
  let expired = false;
  await page.route('**/api/client/install/expired', (route) =>
    route.fulfill({
      json: {
        operationId: 'expired',
        jobId: 'job',
        state: expired ? 'failed' : 'ready',
        ...(expired
          ? { reason: 'CLIENT_INSTALL_ARTIFACT_UNAVAILABLE' }
          : { artifactId: 'artifact' }),
      },
    }),
  );
  await page.route('**/api/client/install/expired/ticket', (route) => {
    expired = true;
    return route.fulfill({ status: 409, json: { code: 'CLIENT_INSTALL_NOT_READY' } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Установить', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Подготовить заново', exact: true })).toBeEnabled();
});

test('lost receipt and changed release offer explicit fresh attempt without retrying network failures', async ({
  page,
}) => {
  await page.addInitScript(() =>
    sessionStorage.setItem(
      'isign-client-install:owner',
      JSON.stringify({ key: 'stale', deviceId: 'binding-device' }),
    ),
  );
  await mockInstaller(page);
  const keys: string[] = [];
  await page.route('**/api/client/install', (route) => {
    const key = route.request().postDataJSON().key;
    keys.push(key);
    return key === 'stale'
      ? route.fulfill({ status: 409, json: { code: 'IDEMPOTENCY_BINDING_MISMATCH' } })
      : route.fulfill({ json: { operationId: 'new', jobId: 'newjob', state: 'queued' } });
  });
  await page.route('**/api/client/install/new', (route) =>
    route.fulfill({ json: { operationId: 'new', jobId: 'newjob', state: 'queued' } }),
  );
  await page.goto('/');
  await page.getByRole('button', { name: 'Подготовить установку', exact: true }).click();
  await page.getByRole('button', { name: 'Подготовить заново', exact: true }).click();
  await expect.poll(() => keys.length).toBe(2);
  expect(keys[0]).toBe('stale');
  expect(keys[1]).not.toBe('stale');
});

test('ready installation keeps its main action within the first iPhone screen', async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockInstaller(page);
  await page.goto('/');
  const action = page.getByRole('button', { name: /^(Подписать клиент|Подготовить установку)$/ });
  await expect(action).toBeEnabled();
  const bounds = await action.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.y + bounds!.height).toBeLessThan(820);
});

test('setup shows one current task instead of future locked forms', async ({ page }) => {
  await mockInstaller(page, {
    apple: { connection: null, shares: [], uploadAllowed: false },
    devices: { devices: [], collectedDevices: [] },
  });
  await page.goto('/');
  await expect(page.getByLabel('Issuer ID', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: /Устройство|Установка/, level: 2 })).toHaveCount(
    0,
  );
  await expect(
    page.getByText('Сначала подключите и подготовьте Apple-аккаунт.', { exact: true }),
  ).toHaveCount(0);
});

test('device changes live in installation settings and return to installation', async ({
  page,
}) => {
  await mockInstaller(page);
  await page.goto('/');
  await expect(page.getByRole('combobox', { name: 'Устройство для установки' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Параметры установки', exact: true }).click();
  await page.getByRole('button', { name: 'Изменить устройство', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Ваш iPhone', exact: true })).toBeVisible();
  await expect(page.getByText('iPhone 16', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Продолжить', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeEnabled();
});
