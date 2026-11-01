import { loginFixture } from './helpers/login';
import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { Service } from '../packages/core/src/application/service';
it('fresh passkey authentication expires at ten minutes and account deletion immediately revokes auth', async () => {
  const db = await createDatabase();
  try {
    let now = 10000;
    const s = new Service(db, {
      now: () => now,
    });
    const a = await loginFixture(s.db, 'one@example.invalid', s.now);
    now += 600000;
    await expect(
      s.disconnect(a.token, a.csrf, 'http://localhost:3000', 'http://localhost:3000'),
    ).rejects.toThrow('FRESH_AUTH_REQUIRED');
    const fresh = await loginFixture(s.db, 'one@example.invalid', s.now);
    await s.deleteAccount(
      fresh.token,
      fresh.csrf,
      'http://localhost:3000',
      'http://localhost:3000',
    );
    await expect(s.session(fresh.token)).rejects.toThrow('UNAUTHENTICATED');
    await expect(s.session(a.token)).rejects.toThrow('UNAUTHENTICATED');
    expect((await db.query('SELECT deleted_at FROM users')).rows[0]).toMatchObject({
      deleted_at: now,
    });
  } finally {
    await db.close();
  }
});
