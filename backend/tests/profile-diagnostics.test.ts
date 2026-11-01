import { it, expect } from 'vitest';
import { mkdtemp, readdir, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createDatabase } from './helpers/database';
import { DeviceCollection } from '../packages/core/src/devices/collection';
import { DeviceOnboarding } from '../packages/core/src/devices/onboarding';
import { hash } from '../packages/core/src/shared/index';
import { ProfileDiagnostics } from '../packages/core/src/devices/profile-diagnostics';
it('temporary diagnostics accepts only a live session-bound profile challenge and stays bounded/private', async () => {
  const db = await createDatabase(),
    directory = await mkdtemp(join(tmpdir(), 'isign-profile-diagnostic-test-'));
  let now = 100;
  try {
    await db.query(
      "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner@synthetic.invalid',0)",
    );
    await db.query(
      'INSERT INTO sessions(token_hash,owner_id,csrf_hash,verified_at,expires_at) VALUES($1,$2,$3,0,999999)',
      [hash('s'.repeat(43)), 'owner', hash('c'.repeat(43))],
    );
    const collection = new DeviceCollection(
      db,
      new DeviceOnboarding(
        db,
        {
          find: async () => [],
          register: async () => {
            throw Error('not used');
          },
        },
        () => now,
      ),
      () => now,
    );
    const challenge = await collection.challenge('owner', 's'.repeat(43));
    const diagnostics = new ProfileDiagnostics(db, () => now, directory);
    expect(
      await diagnostics.capture('a'.repeat(43), Buffer.from('unknown'), 'INVALID_DEVICE_CALLBACK'),
    ).toBe(false);
    for (let n = 0; n < 5; n++) {
      now++;
      expect(
        await diagnostics.capture(
          challenge.challenge,
          Buffer.from('synthetic cms ' + n),
          'INVALID_DEVICE_CALLBACK',
        ),
      ).toBe(true);
    }
    const files = await readdir(directory);
    expect(files).toHaveLength(3);
    expect((await stat(join(directory, files[0]))).mode & 0o077).toBe(0);
    expect((await readFile(join(directory, files.at(-1)!))).toString()).toContain('synthetic cms');
    await db.query('UPDATE sessions SET expires_at=1');
    expect(
      await diagnostics.capture(
        challenge.challenge,
        Buffer.from('revoked'),
        'INVALID_DEVICE_CALLBACK',
      ),
    ).toBe(false);
    expect(await readdir(directory)).toHaveLength(3);
  } finally {
    await db.close();
    await rm(directory, { recursive: true, force: true });
  }
});
