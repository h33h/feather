import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from 'vitest';

test.runIf(process.platform === 'darwin')(
  'release packaging requires an embedded HTTPS service origin',
  () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'isign-package-contract-'));
    try {
      const app = path.join(dir, 'ISignClient.app');
      mkdirSync(app);
      const output = path.join(dir, 'ISignClient.ipa');
      const info = {
        CFBundleIdentifier: 'dev.h33h.feather.isign',
        CFBundlePackageType: 'APPL',
        CFBundleDisplayName: 'iSign Client',
        CFBundleShortVersionString: '2.9.0',
      };
      for (const origin of [
        '',
        '$(ISIGN_SERVICE_ORIGIN)',
        'http://service.test',
        'https://service.test/api',
        'https://u:p@service.test',
        'https://isign.example.invalid',
      ]) {
        writeFileSync(
          path.join(app, 'Info.plist'),
          JSON.stringify({ ...info, ISignServiceOrigin: origin }),
        );
        expect(
          () =>
            execFileSync(
              process.execPath,
              ['backend/scripts/package-client.mjs', '--app', app, '--out', output],
              { stdio: 'pipe' },
            ),
          origin,
        ).toThrow(/CLIENT_SERVICE_ORIGIN_REQUIRED/);
        expect(existsSync(output)).toBe(false);
      }
      writeFileSync(
        path.join(app, 'Info.plist'),
        JSON.stringify({ ...info, ISignServiceOrigin: 'https://service.test:8443' }),
      );
      execFileSync(
        process.execPath,
        ['backend/scripts/package-client.mjs', '--app', app, '--out', output],
        { stdio: 'pipe' },
      );
      expect(existsSync(output)).toBe(true);
      expect(JSON.parse(readFileSync(output + '.json', 'utf8')).serviceOrigin).toBe(
        'https://service.test:8443',
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
