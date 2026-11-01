import { expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { postgresFixture } from '../helpers/postgres';
import { createPersonalRuntimeKernel } from '../../packages/core/src/composition/personal-kernel';
it('initializes a clean PostgreSQL/key/admin and starts without schema mutations', async () => {
  const fixture = await postgresFixture(),
    directory = await mkdtemp(join(tmpdir(), 'isign-install-'));
  const env = {
    NODE_ENV: 'development' as const,
    ISIGN_RUNTIME: 'personal',
    ISIGN_ORIGIN: 'http://localhost:3000',
    DATABASE_URL: fixture.url,
    ISIGN_PERSONAL_DATABASE_TRANSPORT: 'loopback',
    ISIGN_PERSONAL_DATA: join(directory, 'objects'),
    ISIGN_PERSONAL_KEY_FILE: join(directory, 'keys', 'vault'),
    ISIGN_RUNNER_ORIGIN: 'https://runner.synthetic.invalid',
    ISIGN_RUNNER_TOKEN: 'a'.repeat(43),
    ISIGN_RUNNER_AUDIENCE: 'synthetic',
  };
  try {
    await expect(createPersonalRuntimeKernel({ env })).rejects.toThrow('DATABASE_UNINITIALIZED');
    expect(
      (
        await fixture.db.query(
          "SELECT table_name FROM information_schema.tables WHERE table_schema='public'",
        )
      ).rows,
    ).toHaveLength(0);
    const initialized = spawnSync(
      process.execPath,
      ['--import', 'tsx', 'backend/scripts/personal-admin.ts', 'init', 'admin'],
      { env: { ...process.env, ...env }, encoding: 'utf8', timeout: 15000 },
    );
    expect(initialized.status, initialized.stderr).toBe(0);
    expect(JSON.parse(initialized.stdout)).toHaveProperty('token');
    const key = await stat(env.ISIGN_PERSONAL_KEY_FILE);
    expect(key.size).toBe(32);
    expect(key.mode & 0o777).toBe(0o600);
    const kernel = await createPersonalRuntimeKernel({ env });
    try {
      expect((await kernel.db.query('SELECT login_name,role FROM users')).rows).toEqual([
        { login_name: 'admin', role: 'admin' },
      ]);
      expect((await kernel.db.query('SELECT kind FROM sources')).rows).toEqual([{ kind: 'iapps' }]);
      await expect(kernel.service.session('missing')).rejects.toThrow('UNAUTHENTICATED');
      const competing = await createPersonalRuntimeKernel({ env }).catch((error) => error);
      expect(competing.code).toBe('PERSONAL_SINGLE_INSTANCE_REQUIRED');
    } finally {
      await kernel.db.close();
    }
    const reopened = await createPersonalRuntimeKernel({ env });
    await reopened.db.close();
  } finally {
    await fixture.close();
    await rm(directory, { recursive: true, force: true });
  }
}, 30000);
