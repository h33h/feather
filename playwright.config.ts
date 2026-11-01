import { defineConfig } from '@playwright/test';
const port = process.env.ISIGN_BROWSER_PORT ?? '3000';
const baseURL = 'http://localhost:' + port;
export default defineConfig({
  testDir: './backend/tests',
  testMatch: 'browser*.spec.ts',
  workers: 1,
  use: { baseURL, browserName: 'chromium', channel: process.env.PLAYWRIGHT_CHANNEL },
  webServer: {
    command: 'node backend/scripts/browser-server.mjs ' + port,
    gracefulShutdown: { signal: 'SIGTERM', timeout: 35000 },
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120000,
  },
  reporter: 'list',
});
