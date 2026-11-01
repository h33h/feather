import { expect, test, type Page } from '@playwright/test';
import { installerAccount, installerApple, mockInstaller } from './helpers/browser-installer';
import * as errors from '../../web/src/shared/api/errors';
import { parseTeamKey } from '../packages/core/src/apple/onboarding';

const emptyApple = { connection: null, shares: [], uploadAllowed: false };
const emptyDevices = { devices: [], collectedDevices: [] };
async function openConnectedAccount(page: Page) {
  await page.getByRole('button', { name: 'Параметры установки', exact: true }).click();
  await page.getByRole('button', { name: 'Посмотреть аккаунт', exact: true }).click();
}

for (const shared of [false, true]) {
  test(`disconnect ${shared ? 'recipient' : 'owner'} requires a scoped confirmation and cancel keeps access`, async ({
    page,
  }) => {
    const state = await mockInstaller(page, {
      apple: { ...installerApple, connection: { ...installerApple.connection, shared } },
    });
    let disconnects = 0;
    await page.route('**/api/apple/disconnect', async (route) => {
      disconnects++;
      state.apple = emptyApple;
      await route.fulfill({ json: { ok: true } });
    });
    await page.goto('/');
    await openConnectedAccount(page);
    const label = shared ? 'Отказаться от доступа' : 'Отключить свою команду';
    await page.getByRole('button', { name: label, exact: true }).click();
    const dialog = page.getByRole('dialog', { name: label + '?', exact: true });
    await expect(dialog).toBeVisible();
    expect(disconnects).toBe(0);
    await expect(dialog).toContainText('TEAM123456');
    if (shared) {
      await expect(dialog).toContainText('только ваш доступ');
      await expect(dialog).toContainText('Подключение владельца');
      await expect(dialog).not.toContainText('помечены для удаления');
    } else {
      await expect(dialog).toContainText('всех профилей');
      await expect(dialog).toContainText('выданные доступы');
      await expect(dialog).toContainText('помечены для удаления');
      await expect(dialog).toContainText('автоматически не отзываются');
    }
    await expect(dialog.getByRole('button', { name: /Закрыть|Отмена/ }).first()).toBeFocused();
    await dialog.getByRole('button', { name: 'Отмена', exact: true }).click();
    await expect(dialog).not.toBeVisible();
    expect(disconnects).toBe(0);
    await expect(page.getByRole('button', { name: label, exact: true })).toBeFocused();
    await page.getByRole('button', { name: label, exact: true }).click();
    await dialog.getByRole('button', { name: label, exact: true }).click();
    await expect.poll(() => disconnects).toBe(1);
    await expect(
      page.getByRole('heading', { name: 'Подключите аккаунт', exact: true }),
    ).toBeVisible();
  });
}

test('disconnect shows pending and safe local errors without silently closing the dialog', async ({
  page,
}) => {
  await mockInstaller(page);
  let finish: (() => void) | undefined;
  await page.route('**/api/apple/disconnect', async (route) => {
    await new Promise<void>((resolve) => {
      finish = resolve;
    });
    await route.fulfill({ status: 503, json: { code: 'UNEXPECTED_SECRET_FAILURE' } });
  });
  await page.goto('/');
  await openConnectedAccount(page);
  await page.getByRole('button', { name: 'Отключить свою команду', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: 'Отключить свою команду', exact: true }).click();
  await expect(dialog.getByRole('status')).toContainText('Отключаем');
  await expect(dialog.getByRole('button', { name: 'Отмена', exact: true })).toBeDisabled();
  await expect(
    dialog.getByRole('button', { name: 'Закрыть: Отключить свою команду?' }),
  ).toBeDisabled();
  finish?.();
  await expect(dialog.getByRole('alert')).toContainText('Не удалось отключить');
  await expect(dialog).not.toContainText('unexpected');
  await expect(dialog.getByRole('button', { name: 'Отмена', exact: true })).toBeEnabled();
});

test('receiving access copies the menu ID and reports failed refresh without inventing grant state', async ({
  page,
  context,
}) => {
  const state = await mockInstaller(page, { apple: emptyApple, devices: emptyDevices });
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/');
  await page.locator('.installer-profile-trigger').click();
  await expect(page.locator('[data-profile-id]')).toHaveText('profile-public');
  await page.getByRole('button', { name: 'Скопировать ID профиля', exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('profile-public');
  await page.keyboard.press('Escape');
  await page.route('**/api/apple', (route) =>
    route.fulfill({ status: 503, json: { code: 'SERVER_BUSY' } }),
  );
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(
    page.getByRole('alert').filter({ hasText: 'Не удалось обновить аккаунт' }),
  ).toBeVisible();
  await expect(page.getByText('Доступ пока не предоставлен', { exact: false })).toHaveCount(0);
  await page.unroute('**/api/apple');
  state.apple = { ...installerApple, connection: { ...installerApple.connection, shared: true } };
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.getByRole('heading', { name: 'Добавьте iPhone', exact: true })).toBeVisible();
});

test('own team keeps optional official help collapsed and omits removed captions', async ({
  page,
}) => {
  await mockInstaller(page, { apple: emptyApple, devices: emptyDevices });
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Доступ от владельца', exact: true })).toHaveCount(
    0,
  );
  await expect(page.getByText('Приватный ключ будет отправлен', { exact: false })).toHaveCount(0);
  const help = page.getByText(
    'Users and Access → Integrations → App Store Connect API → Team Keys',
    { exact: false },
  );
  await expect(help).toBeHidden();
  await page.getByText('Где взять ключ?', { exact: true }).click();
  await expect(help).toBeVisible();
  await expect(
    page.getByRole('link', { name: 'Создание Team API Key — Apple', exact: true }),
  ).toHaveAttribute(
    'href',
    'https://developer.apple.com/help/app-store-connect/get-started/app-store-connect-api',
  );
});

test('credential field feedback follows the actual server identifier rules without uploading invalid fields', async ({
  page,
}) => {
  await mockInstaller(page, { apple: emptyApple, devices: emptyDevices });
  let connects = 0;
  await page.route('**/api/apple/connect', (route) => {
    connects++;
    return route.fulfill({ json: { ok: true } });
  });
  await page.goto('/');
  const issuer = page.getByLabel('Issuer ID', { exact: true });
  const key = page.getByLabel('Key ID', { exact: true });
  await issuer.fill('not-a-uuid');
  await issuer.blur();
  await expect(issuer).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText('Issuer ID состоит из 36 символов', { exact: false })).toBeVisible();
  await key.fill('short');
  await key.blur();
  await expect(key).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText('Key ID состоит из 10 букв и цифр', { exact: false })).toBeVisible();
  await page.getByLabel('Ключ .p8', { exact: true }).setInputFiles({
    name: 'AuthKey_ABC123DEF4.p8',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('synthetic-only-p8'),
  });
  await page.getByRole('button', { name: 'Подключить', exact: true }).click();
  expect(connects).toBe(0);
  // These are the same invalid inputs rejected by the real server parser.
  expect(() =>
    parseTeamKey({ issuerId: 'not-a-uuid', keyId: 'short', filename: 'x.p8', p8: Buffer.alloc(0) }),
  ).toThrow('INVALID_ISSUER_ID');
  expect(() =>
    parseTeamKey({
      issuerId: '12345678-1234-1234-1234-123456789abc',
      keyId: 'short',
      filename: 'x.p8',
      p8: Buffer.alloc(0),
    }),
  ).toThrow('INVALID_KEY_ID');
  await issuer.fill('12345678-1234-1234-1234-123456789abc');
  await issuer.blur();
  await key.fill('abc123def4');
  await key.blur();
  await expect(issuer).not.toHaveAttribute('aria-invalid', 'true');
  await expect(key).not.toHaveAttribute('aria-invalid', 'true');
  expect(connects).toBe(0);
});

test('rejected private key has an associated field error and is cleared after submission', async ({
  page,
}) => {
  await mockInstaller(page, { apple: emptyApple, devices: emptyDevices });
  await page.route('**/api/apple/connect', (route) =>
    route.fulfill({ status: 400, json: { code: 'INVALID_P8' } }),
  );
  await page.goto('/');
  await page.getByLabel('Issuer ID', { exact: true }).fill('12345678-1234-1234-1234-123456789abc');
  await page.getByLabel('Key ID', { exact: true }).fill('ABC123DEF4');
  const input = page.getByLabel('Ключ .p8', { exact: true });
  await input.setInputFiles({
    name: 'AuthKey_ABC123DEF4.p8',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('synthetic-only-p8'),
  });
  await page.getByRole('button', { name: 'Подключить', exact: true }).click();
  await expect(input).toHaveAttribute('aria-invalid', 'true');
  await expect(input).toHaveAttribute('aria-describedby', /p8-error/);
  await expect(page.getByRole('alert').filter({ hasText: 'исходный файл .p8' })).toBeVisible();
  await expect
    .poll(() => input.evaluate((element) => (element as HTMLInputElement).files?.length))
    .toBe(0);
  await expect(page.getByRole('button', { name: 'Подключить', exact: true })).toBeDisabled();
});

test('reachable error copy avoids retired web paths and provides safe Russian fallbacks', () => {
  const reachable = [
    'RELEASE_UNAVAILABLE',
    'APPLE_CONNECTION_REQUIRED',
    'CONNECTION_UNAVAILABLE',
    'CONNECTION_CHANGED',
    'APPLE_ACCESS_CHANGED',
    'CERTIFICATE_CREATION_CONSENT_REQUIRED',
    'ACTIVE_JOB_EXISTS',
    'TEAM_PROOF_REQUIRED',
    'TEAM_UNAVAILABLE',
    'SOURCE_EXPIRED',
    'HANDOFF_INVALID',
    'APPLE_ACCESS_REQUIRED',
    'CERTIFICATE_REQUIRED',
    'RUNNER_REQUEST_REJECTED',
  ];
  for (const code of reachable) {
    expect(errors.messages[code], code).not.toMatch(
      /каталог|настройк|Мои приложения|загруз|выберите файл/i,
    );
  }
  const mapper = (errors as Record<string, unknown>).installerErrorMessage;
  expect(typeof mapper).toBe('function');
  if (typeof mapper !== 'function') return;
  for (const code of [
    'APPLE_AUTH_FAILED',
    'APPLE_RATE_LIMITED',
    'INVALID_ISSUER_ID',
    'INVALID_P8',
    'BOOTSTRAP_BROKER_UNAVAILABLE',
    'SECRET_UNAVAILABLE',
  ]) {
    expect(mapper(code), code).toMatch(/[А-Яа-я]/);
    expect(mapper(code), code).not.toContain(code);
    expect(errors.messages[code], code).toBeTruthy();
  }
  expect(mapper('NEW_UNKNOWN_MACHINE_FAILURE')).toBe(
    'Действие не выполнено. Обновите данные и повторите попытку.',
  );
  expect(mapper(null, 'Проверьте доступ ещё раз.')).toBe('Проверьте доступ ещё раз.');
});

for (const code of ['APPLE_ACCESS_ACTION_REQUIRED', 'UNRECOGNIZED_APPLE_FAILURE']) {
  test(`connection state ${code} offers Russian next steps without exposing machine tokens`, async ({
    page,
  }) => {
    await mockInstaller(page, {
      apple: {
        ...installerApple,
        connection: {
          ...installerApple.connection,
          state: 'action_required',
          identityReady: false,
          last_error: code,
        },
      },
    });
    await page.goto('/');
    const status = page.locator('.installer-account-state');
    await expect(status).toContainText(
      code === 'APPLE_ACCESS_ACTION_REQUIRED' ? 'проверить ключ' : 'Проверьте доступ',
    );
    await expect(status).not.toContainText(code.toLowerCase().replaceAll('_', ' '));
    await expect(status).not.toContainText('настройк');
  });
}

for (const change of ['logout', 'owner', 'binding']) {
  test(`a private-key read finishing after ${change} cannot submit the previous account's key`, async ({
    page,
  }) => {
    const state = await mockInstaller(page, { apple: emptyApple, devices: emptyDevices });
    await page.addInitScript(() => {
      const testState = window as typeof window & {
        finishKeyRead?: () => void;
        keyReadStarted?: boolean;
        lateConnects?: number;
      };
      testState.lateConnects = 0;
      const fetchOriginal = window.fetch;
      window.fetch = (...args) => {
        if (String(args[0]).endsWith('/api/apple/connect')) testState.lateConnects!++;
        return fetchOriginal(...args);
      };
      File.prototype.text = () =>
        new Promise<string>((resolve) => {
          testState.keyReadStarted = true;
          testState.finishKeyRead = () => resolve('synthetic-only-delayed-p8');
        });
    });
    await page.goto('/');
    await page
      .getByLabel('Issuer ID', { exact: true })
      .fill('12345678-1234-1234-1234-123456789abc');
    await page.getByLabel('Key ID', { exact: true }).fill('ABC123DEF4');
    await page.getByLabel('Ключ .p8', { exact: true }).setInputFiles({
      name: 'AuthKey_ABC123DEF4.p8',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('synthetic-only-p8'),
    });
    await page.getByRole('button', { name: 'Подключить', exact: true }).click();
    await expect
      .poll(() =>
        page.evaluate(
          () => (window as typeof window & { keyReadStarted?: boolean }).keyReadStarted,
        ),
      )
      .toBe(true);
    if (change === 'logout') {
      await page.locator('.installer-profile-trigger').click();
      await page.getByRole('button', { name: 'Выйти', exact: true }).click();
      await expect(
        page.getByRole('button', { name: 'Войти с passkey', exact: true }),
      ).toBeVisible();
    } else if (change === 'owner') {
      await page.route('**/api/session', (route) =>
        route.fulfill({
          json: {
            ...installerAccount,
            profile: {
              ...installerAccount.profile,
              id: 'next-owner',
              loginName: 'next-owner',
              publicProfileId: 'profile-next',
            },
          },
        }),
      );
      await page.evaluate(() => window.dispatchEvent(new Event('focus')));
      await expect(page.locator('.installer-profile-trigger')).toHaveText('profile-next');
      await expect(page.getByLabel('Issuer ID', { exact: true })).toHaveValue('');
    } else {
      state.apple = {
        ...installerApple,
        connection: {
          ...installerApple.connection,
          state: 'action_required',
          identityReady: false,
          last_error: 'CERTIFICATE_REQUIRED',
          shared: true,
        },
      };
      await page.evaluate(() => window.dispatchEvent(new Event('focus')));
      await expect(
        page.getByText('Владелец команды должен завершить', { exact: false }),
      ).toBeVisible();
    }
    const attempted = await page.evaluate(async () => {
      const testState = window as typeof window & {
        finishKeyRead?: () => void;
        lateConnects?: number;
      };
      testState.finishKeyRead?.();
      // Flush the read continuation before observing whether it entered fetch.
      await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
      return testState.lateConnects;
    });
    expect(attempted).toBe(0);
  });
}

test('a pending disconnect keeps its original request but drops confirmation and error effects after rebinding', async ({
  page,
}) => {
  const state = await mockInstaller(page);
  let entered!: () => void, release!: () => void, completed!: () => void;
  const requested = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  const responded = new Promise<void>((resolve) => {
    completed = resolve;
  });
  let disconnects = 0;
  await page.route('**/api/apple/disconnect', async (route) => {
    disconnects++;
    entered();
    await delayed;
    await route.fulfill({ status: 503, json: { code: 'OLD_CONNECTION_FAILURE' } });
    completed();
  });
  await page.goto('/');
  await openConnectedAccount(page);
  await page.getByRole('button', { name: 'Отключить свою команду', exact: true }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: 'Отключить свою команду', exact: true })
    .click();
  await requested;
  try {
    state.apple = {
      ...installerApple,
      connection: { ...installerApple.connection, id: 'next-team', team_id: 'OTHERTEAM1' },
    };
    await page.evaluate(() => window.dispatchEvent(new Event('focus')));
    await openConnectedAccount(page);
    await expect(page.getByText('OTHERTEAM1', { exact: true })).toBeVisible();
    await expect(page.getByRole('dialog')).not.toBeVisible();
  } finally {
    release();
  }
  await responded;
  await expect(
    page.getByRole('button', { name: 'Отключить свою команду', exact: true }),
  ).toBeEnabled();
  await expect(page.getByText('Не удалось отключить доступ', { exact: false })).toHaveCount(0);
  expect(disconnects).toBe(1);
});
