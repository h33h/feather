import { expect, test } from '@playwright/test';
import { installerAccount, installerDevices, mockInstaller } from './helpers/browser-installer';

test('approved welcome centers the mark and keeps its actions at the bottom', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockInstaller(page, { authenticated: false });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'iSign', exact: true })).toBeVisible();
  await expect(page.getByRole('img', { name: 'Знак iSign', exact: true })).toBeVisible();
  await expect(page.locator('.installer-header')).toHaveCount(0);
  await expect(page.getByText(/Ваш клиент для iPhone|Войдите для установки/)).toHaveCount(0);
  const action = page.getByRole('button', { name: 'Войти с passkey', exact: true });
  await expect(action).toBeEnabled();
  expect((await action.boundingBox())!.y).toBeGreaterThan(620);
  await page.getByRole('button', { name: 'Есть приглашение', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Первый вход', exact: true })).toBeVisible();
  await expect(page.getByLabel('Код приглашения', { exact: true })).toBeVisible();
  await expect(page.getByText('Введите код из приглашения', { exact: true })).toHaveCount(0);
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'iSign', exact: true })).toBeVisible();
});

test('approved profile uses a text ID, clipboard icon and persisted theme switch', async ({
  page,
  context,
}) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await mockInstaller(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'profile-public', exact: true }).click();
  await expect(page.locator('[data-profile-id]')).toHaveText('profile-public');
  expect(await page.locator('[data-profile-id]').evaluate((el) => el.tagName)).toBe('SPAN');
  await page.getByRole('button', { name: 'Скопировать ID профиля', exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('profile-public');
  await expect(page.getByText(/ID профиля|ID скопирован/)).toHaveCount(0);
  await expect(page.getByRole('combobox', { name: 'Цветовая тема' })).toHaveCount(0);
  await page.getByRole('switch', { name: 'Тёмная тема', exact: true }).check();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('switch', { name: 'Тёмная тема' })).toBeHidden();
  await expect(page.getByRole('button', { name: 'profile-public', exact: true })).toBeFocused();
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});

test('approved account has one form and no owner tab or key transfer captions', async ({
  page,
}) => {
  await mockInstaller(page, {
    apple: { connection: null, shares: [], uploadAllowed: false },
    devices: { devices: [], collectedDevices: [] },
  });
  await page.goto('/');
  await expect(
    page.getByRole('heading', { name: 'Подключите аккаунт', exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel('Issuer ID', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Ключ .p8', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Доступ от владельца' })).toHaveCount(0);
  await expect(
    page.getByText(/Приватный ключ будет отправлен|Нужна команда Apple Developer Program/),
  ).toHaveCount(0);
  await expect(
    page.locator('footer').getByRole('button', { name: 'Подключить', exact: true }),
  ).toBeDisabled();
});

test('registration shows UDID without a consent checkbox and boxes Apple waiting', async ({
  page,
}) => {
  await mockInstaller(page, {
    devices: {
      devices: [{ ...installerDevices.devices[0], status: 'apple_processing', selected: false }],
      collectedDevices: [
        {
          id: 'identity',
          name: 'iPhone 16',
          udid: '00008140-001234567890ABCD',
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
              status: 'apple_processing',
              shared: false,
            },
          ],
        },
      ],
    },
  });
  await page.goto('/');
  await expect(page.getByText('00008140-001234567890ABCD', { exact: true })).toBeVisible();
  await expect(page.getByRole('checkbox')).toHaveCount(0);
  const waiting = page.getByRole('status').filter({ hasText: 'Ожидаем Apple' });
  await expect(waiting).toBeVisible();
  expect(await waiting.evaluate((el) => getComputedStyle(el).borderTopWidth)).toBe('1px');
});

test('profile ID stays selectable as plain text in the open dropdown', async ({ page }) => {
  await mockInstaller(page);
  await page.goto('/');
  await page.locator('.installer-profile-trigger').click();
  await page.locator('[data-profile-id]').click();
  await expect(page.getByRole('switch', { name: 'Тёмная тема', exact: true })).toBeVisible();
});

test('browser Back after logout cannot reopen authenticated screens', async ({ page }) => {
  await mockInstaller(page);
  await page.goto('/');
  await page.getByRole('button', { name: 'Параметры установки', exact: true }).click();
  await page.locator('.installer-profile-trigger').click();
  await page.getByRole('button', { name: 'Выйти', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'iSign', exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole('heading', { name: 'iSign', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Установка через QR' })).toHaveCount(0);
});

test('a long profile ID never squeezes the Back action on a narrow iPhone', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 568 });
  await mockInstaller(page);
  await page.route('**/api/session', (route) =>
    route.fulfill({
      json: {
        ...installerAccount,
        profile: {
          ...installerAccount.profile,
          publicProfileId: 'profile_8bfa1729d0464ea3b327c6f519ce280a',
        },
      },
    }),
  );
  await page.goto('/');
  const back = page.getByRole('button', { name: 'Назад', exact: true });
  await expect(back).toBeVisible();
  expect((await back.boundingBox())!.height).toBeLessThanOrEqual(44);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await back.click();
  await expect(page.getByRole('heading', { name: 'Ваш iPhone', exact: true })).toBeVisible();
});
