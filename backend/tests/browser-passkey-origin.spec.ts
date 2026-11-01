import { expect, test } from '@playwright/test';
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
test('browser passkey registration is cryptographically verified against the configured origin', async ({
  page,
  context,
  baseURL,
}) => {
  const origin = new URL(baseURL!).origin,
    rpID = new URL(origin).hostname;
  const options = await generateRegistrationOptions({
    rpName: 'iSign test',
    rpID,
    userName: 'invited',
    userID: new TextEncoder().encode('invited'),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    attestationType: 'none',
  });
  const client = await context.newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  let verified = false;
  await page.route(/\/api\/(session|library|apple|devices|sources)$/, (route) =>
    route.fulfill(
      verified
        ? {
            json: {
              csrf: 'csrf',
              profile: { id: 'invited', loginName: 'invited', role: 'user' },
              capabilities: { runner: false },
              authenticated: true,
            },
          }
        : { status: 401, json: { code: 'UNAUTHENTICATED' } },
    ),
  );
  await page.route('**/api/auth/passkey/register-options', (route) =>
    route.fulfill({ json: { requestId: 'request', options } }),
  );
  await page.route('**/api/auth/passkey/register', async (route) => {
    const result = await verifyRegistrationResponse({
      response: route.request().postDataJSON().response,
      expectedChallenge: options.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
    verified = result.verified;
    return route.fulfill({ json: { authenticated: verified, csrf: 'csrf' } });
  });
  await page.route('**/api/client/release', (route) =>
    route.fulfill({ json: { name: 'iSign Client', available: false } }),
  );
  await page.route('**/api/apple', (route) =>
    route.fulfill({ json: { connection: null, shares: [], uploadAllowed: false } }),
  );
  await page.route('**/api/devices', (route) =>
    route.fulfill({ json: { devices: [], collectedDevices: [] } }),
  );
  await page.goto('/');
  await page.getByText('Первый вход', { exact: true }).click();
  await page.getByLabel('Код приглашения', { exact: true }).fill('a'.repeat(43));
  await page.getByRole('button', { name: 'Создать passkey', exact: true }).click();
  await expect.poll(() => verified).toBe(true);
  await expect(page.getByRole('heading', { name: 'iSign Client', exact: true })).toBeVisible();
});
