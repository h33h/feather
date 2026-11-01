import { loginFixture, connectionFixture, deviceFixture } from './helpers/login';
import { afterEach, describe, it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { Service } from '../packages/core/src/application/service';
const closers: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
});
async function harness() {
  const db = await createDatabase();
  closers.push(() => db.close());
  let now = 1000000;
  const mail = new Map<string, string>();
  const service = new Service(db, {
    now: () => now,
  });
  return { db, service, mail, advance: (ms: number) => (now += ms) };
}
async function login(h: Awaited<ReturnType<typeof harness>>, email = 'one@example.invalid') {
  return loginFixture(h.service.db, email, h.service.now);
}
describe('session isolation and database ownership', () => {
  it('hashes session values at rest', async () => {
    const h = await harness();
    const s = await login(h);
    const rows = await h.db.query('SELECT token_hash FROM sessions');
    expect(rows.rows).toHaveLength(1);
    expect(JSON.stringify(rows.rows)).not.toContain(s.token);
    expect(await h.service.session(s.token)).toMatchObject({ ownerId: s.ownerId });
  });
  it('rejects foreign device through API and PostgreSQL foreign key', async () => {
    const h = await harness();
    const a = await login(h);
    const b = await login(h, 'two@example.invalid');
    const c = await connectionFixture(h.service.db, a.ownerId, 'TEAM-A');
    const d = await deviceFixture(h.service.db, a.ownerId, c.id, 'Test iPhone', '27.0');
    await expect(h.service.selectDevice(b.ownerId, d.id)).rejects.toThrow('NOT_FOUND');
    await expect(
      h.db.query(
        'INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,os_version) VALUES ($1,$2,$3,$2,$4,$5,$6)',
        ['foreign', b.ownerId, c.id, 'foreign', 'ready', '27.0'],
      ),
    ).rejects.toThrow();
  });
  it('prevents another owner attaching the same Apple team', async () => {
    const h = await harness();
    const a = await login(h);
    const b = await login(h, 'two@example.invalid');
    await connectionFixture(h.service.db, a.ownerId, 'TEAM-A');
    await expect(connectionFixture(h.service.db, b.ownerId, 'TEAM-A')).rejects.toThrow(
      'duplicate key',
    );
  });
  it('requires both origin and per-session CSRF for writes', async () => {
    const h = await harness();
    const s = await login(h);
    await expect(
      h.service.authorizeWrite(s.token, 'bad', 'http://localhost:3000', 'http://localhost:3000'),
    ).rejects.toThrow('CSRF');
    await expect(
      h.service.authorizeWrite(s.token, s.csrf, 'https://evil.invalid', 'http://localhost:3000'),
    ).rejects.toThrow('CSRF');
    expect(
      (
        await h.service.authorizeWrite(
          s.token,
          s.csrf,
          'http://localhost:3000',
          'http://localhost:3000',
        )
      ).ownerId,
    ).toBe(s.ownerId);
  });
});
