import { ConnectionLifecycle } from '../packages/core/src/apple/connection-lifecycle';
import { loginFixture, connectionFixture } from './helpers/login';
import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { SessionService } from '../packages/core/src/auth/sessions';
import { Vault } from '../packages/core/src/apple/vault';
import { SecretDeletionWorker } from '../packages/core/src/apple/secret-deletion';
it('persists secret deletion before disconnect and retries failed revocation without releasing ciphertext', async () => {
  const db = await createDatabase();
  try {
    let now = 10000,
      fail = true,
      revoked = 0;
    const s = new SessionService(db, {
      now: () => now,
    });
    const session = await loginFixture(db, 'delete@example.invalid', s.now),
      c = await connectionFixture(db, session.ownerId, 'TEAM-DELETE');
    const vault = new Vault(
      db,
      {
        generate: async () => ({ plaintext: Buffer.alloc(32, 7), wrapped: 'synthetic-wrapped' }),
        unwrap: async () => Buffer.alloc(32, 7),
        revoke: async () => {
          if (fail) throw new Error('synthetic ledger outage');
          revoked++;
        },
      },
      () => now,
    );
    const secret = await vault.seal(
      session.ownerId,
      c.id,
      'distribution-key',
      Buffer.from('synthetic fixture'),
    );
    await new ConnectionLifecycle(db, () => s.now, s).disconnect(
      session.token,
      session.csrf,
      'http://localhost:3000',
      'http://localhost:3000',
    );
    expect(
      (
        await db.query<{ deleted_at: number }>('SELECT deleted_at FROM secrets WHERE id=$1', [
          secret,
        ])
      ).rows[0].deleted_at,
    ).toBe(now);
    const worker = new SecretDeletionWorker(db, vault, () => now);
    expect(await worker.runOne()).toBe(false);
    expect(
      (
        await db.query<{ ciphertext: string }>('SELECT ciphertext FROM secrets WHERE id=$1', [
          secret,
        ])
      ).rows[0].ciphertext.length,
    ).toBeGreaterThan(0);
    fail = false;
    now += 60001;
    expect(await worker.runOne()).toBe(true);
    expect(revoked).toBe(1);
    expect(
      (
        await db.query<{ ciphertext: string }>('SELECT ciphertext FROM secrets WHERE id=$1', [
          secret,
        ])
      ).rows[0].ciphertext,
    ).toBe('');
    expect(await worker.runOne()).toBe(false);
  } finally {
    await db.close();
  }
});
