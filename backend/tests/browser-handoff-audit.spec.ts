import { expect, test } from '@playwright/test';
import { installerAccount, mockInstaller } from './helpers/browser-installer';
async function readyOperation(page: import('@playwright/test').Page, runner = true) {
  await page.addInitScript(() =>
    sessionStorage.setItem(
      'isign-client-install:owner',
      JSON.stringify({ key: 'ready', deviceId: 'binding-device', operationId: 'ready' }),
    ),
  );
  await mockInstaller(page);
  await page.route('**/api/session', (route) =>
    route.fulfill({
      json: { ...installerAccount, capabilities: { ...installerAccount.capabilities, runner } },
    }),
  );
  await page.route('**/api/client/install/ready', (route) =>
    route.fulfill({
      json: { operationId: 'ready', jobId: 'job', state: 'ready', artifactId: 'artifact' },
    }),
  );
}
test('existing ready artifact can be delivered without a new-signing capability', async ({
  page,
}) => {
  await readyOperation(page, false);
  await page.goto('/');
  await expect(
    page.getByRole('button', { name: 'Показать QR установки', exact: true }),
  ).toBeEnabled();
});
test('ready page opens the configured client without manual server setup', async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'userAgent', {
      configurable: true,
      value:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile Safari/604.1',
    });
  });
  await readyOperation(page);
  await page.goto('/');
  await expect(page.getByText('После установки', { exact: true })).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Открыть iSign Client', exact: true }),
  ).toHaveAttribute('href', 'isign-feather://open');
  await expect(page.getByRole('textbox', { name: 'Адрес сервера iSign', exact: true })).toHaveCount(
    0,
  );
  await expect(page.getByText(/с тем же passkey/)).toBeVisible();
});
test('unavailable new preparation explains its cause and can recheck availability', async ({
  page,
}) => {
  await mockInstaller(page, { release: false });
  await page.goto('/');
  await expect(
    page.getByRole('button', { name: 'Проверить доступность', exact: true }),
  ).toBeVisible();
  await expect(page.getByText(/администратор.*опубликовать/i)).toBeVisible();
});

test('resumed artifact identifies its own version instead of a newer published template', async ({
  page,
}) => {
  await readyOperation(page);
  await page.route('**/api/client/install/ready', (route) =>
    route.fulfill({
      json: {
        operationId: 'ready',
        jobId: 'job',
        state: 'ready',
        artifactId: 'artifact',
        version: '2.8.0',
      },
    }),
  );
  await page.goto('/');
  await expect(page.getByText(/Версия 2\.8\.0/)).toBeVisible();
});

test('desktop promotes QR transfer while iOS exposes direct installation', async ({ page }) => {
  await readyOperation(page);
  await page.goto('/');
  await expect(
    page.getByRole('button', { name: 'Показать QR установки', exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Установить на устройство', exact: true }),
  ).toHaveCount(0);
  await page.addInitScript(() =>
    Object.defineProperty(navigator, 'userAgent', {
      configurable: true,
      value:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Mobile Safari/604.1',
    }),
  );
  await page.reload();
  await expect(
    page.getByRole('button', { name: 'Установить на устройство', exact: true }),
  ).toBeVisible();
});

test('preparation explains missing signing service and can refresh its capability', async ({
  page,
}) => {
  await mockInstaller(page);
  let runner = false;
  await page.route('**/api/session', (route) =>
    route.fulfill({
      json: { ...installerAccount, capabilities: { ...installerAccount.capabilities, runner } },
    }),
  );
  await page.goto('/');
  await expect(page.getByText(/Сервер сейчас не подготавливает новые установки/)).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeDisabled();
  runner = true;
  await page.getByRole('button', { name: 'Проверить доступность', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeEnabled();
});

test('completed summaries expose the actual selected team and device in accessible names', async ({
  page,
}) => {
  await mockInstaller(page);
  await page.goto('/');
  await expect(
    page.getByRole('button', {
      name: 'Изменить: Команда Apple Developer, TEAM123456',
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    page.getByRole('button', { name: 'Изменить: Устройство, iPhone 16 · iOS 18.0', exact: true }),
  ).toBeVisible();
});

test('unpublished source can become available without reloading or losing selected device', async ({
  page,
}) => {
  await mockInstaller(page);
  let available = false;
  await page.route('**/api/client/release', (route) =>
    route.fulfill({
      json: {
        name: 'iSign Client',
        available,
        ...(available ? { version: '2.9.0' } : { reason: 'CLIENT_RELEASE_NOT_CONFIGURED' }),
      },
    }),
  );
  await page.goto('/');
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeDisabled();
  available = true;
  await page.getByRole('button', { name: 'Проверить доступность', exact: true }).click();
  await expect(
    page.getByRole('button', { name: 'Подготовить установку', exact: true }),
  ).toBeEnabled();
  await expect(page.getByRole('button', { name: /Изменить: Устройство, iPhone 16/ })).toBeVisible();
});

test('a ready verified operation remains deliverable if no new source is published', async ({
  page,
}) => {
  await readyOperation(page);
  await page.route('**/api/client/release', (route) =>
    route.fulfill({
      json: { name: 'iSign Client', available: false, reason: 'CLIENT_RELEASE_NOT_CONFIGURED' },
    }),
  );
  await page.goto('/');
  await expect(
    page.getByRole('button', { name: 'Показать QR установки', exact: true }),
  ).toBeEnabled();
  await expect(page.getByText('Версия клиента ещё не опубликована.', { exact: true })).toHaveCount(
    0,
  );
});

for (const delayed of [false, true]) {
  test(`operation replacement never revives an old ${delayed ? 'delayed' : 'visible'} QR`, async ({
    page,
    baseURL,
  }) => {
    await readyOperation(page);
    let invalid = false,
      release!: () => void,
      requested!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve)),
      entered = new Promise<void>((resolve) => (requested = resolve));
    await page.route('**/api/client/install/ready', (route) =>
      route.fulfill({
        json: {
          operationId: 'ready',
          jobId: 'old',
          state: invalid ? 'failed' : 'ready',
          ...(invalid ? { reason: 'CLIENT_INSTALL_ARTIFACT_UNAVAILABLE' } : { artifactId: 'old' }),
        },
      }),
    );
    await page.route('**/api/client/install/ready/ticket', async (route) => {
      requested();
      if (delayed) await held;
      await route.fulfill({
        json: {
          installUrl:
            'itms-services://?action=download-manifest&url=' +
            encodeURIComponent(baseURL + '/install/old/manifest.plist'),
          handoffUrl: baseURL + '/handoff/old',
          expiresAt: Date.now() + 60000,
          qrSvg:
            '<svg xmlns="http://www.w3.org/2000/svg" width="192" height="192"><rect width="192" height="192" fill="white"/></svg>',
        },
      });
    });
    await page.route('**/api/client/install', (route) =>
      route.fulfill({ json: { operationId: 'replacement', jobId: 'new', state: 'queued' } }),
    );
    await page.route('**/api/client/install/replacement', (route) =>
      route.fulfill({
        json: { operationId: 'replacement', jobId: 'new', state: 'ready', artifactId: 'new' },
      }),
    );
    await page.goto('/');
    await page.getByRole('button', { name: 'Показать QR установки', exact: true }).click();
    await entered;
    if (!delayed)
      await expect(
        page.getByRole('img', { name: 'QR установки iSign Client', exact: true }),
      ).toBeVisible();
    invalid = true;
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await expect(
      page.getByRole('button', { name: 'Подготовить заново', exact: true }),
    ).toBeVisible();
    release();
    await page.getByRole('button', { name: 'Подготовить заново', exact: true }).click();
    await expect(
      page.getByRole('button', { name: 'Показать QR установки', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('img', { name: 'QR установки iSign Client', exact: true }),
    ).toHaveCount(0);
    await expect(page.getByRole('textbox', { name: 'Ссылка установки', exact: true })).toHaveCount(
      0,
    );
  });
}
