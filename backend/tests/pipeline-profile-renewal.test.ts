import { ownAuthority } from './helpers/seed-authority';
import { it, expect } from 'vitest';
import { createDatabase } from './helpers/database';
import { ProfileRenewal } from '../packages/core/src/apple/profile-renewal';
it('renews only a publicly expired own exact profile and reuses stable revision after unknown creation', async () => {
  const db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','profile@b.c',0)");
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
    );
    await ownAuthority(db);
    const renewal = new ProfileRenewal({ db, now: () => 10000 });
    const binding = { ownerId: 'o', connectionId: 'c', generation: 1 };
    const found = new Map([
      [
        'own-base',
        {
          id: 'old',
          attributes: { name: 'own-base', expirationDate: new Date(9000).toISOString() },
        },
      ],
    ]);
    const lookup = async (_bundle: string, name: string) =>
      found.has(name) ? [found.get(name)!] : [];
    const current = async () => {};
    expect(
      await Promise.all([
        renewal.chooseName(binding, 'own-base', 'bundle', lookup, current),
        renewal.chooseName(binding, 'own-base', 'bundle', lookup, current),
      ]),
    ).toEqual(['own-base-r1', 'own-base-r1']);
    found.set('own-base-r1', {
      id: 'new',
      attributes: { name: 'own-base-r1', expirationDate: new Date(20000).toISOString() },
    });
    expect(await renewal.chooseName(binding, 'own-base', 'bundle', lookup, current)).toBe(
      'own-base-r1',
    );
    found.set('own-base-r1', {
      id: 'new',
      attributes: { name: 'own-base-r1', expirationDate: new Date(9500).toISOString() },
    });
    expect(await renewal.chooseName(binding, 'own-base', 'bundle', lookup, current)).toBe(
      'own-base-r2',
    );
    expect(found.has('own-base')).toBe(true);
    expect(
      (
        await db.query<{ resource_id: string }>(
          "SELECT resource_id FROM provisioning_operations WHERE kind='profile-renewal'",
        )
      ).rows[0].resource_id,
    ).toBe('2');
  } finally {
    await db.close();
  }
});
it('does not invent profile validity or change revision from browser-like resource claim', async () => {
  const db = await createDatabase();
  try {
    const renewal = new ProfileRenewal({ db, now: () => 10000 });
    await expect(
      renewal.chooseName(
        { ownerId: 'o', connectionId: 'c', generation: 1 },
        'own',
        'bundle',
        async () => [{ id: 'bad', attributes: { name: 'own', expirationDate: 'unknown' } }],
        async () => {},
      ),
    ).rejects.toThrow('PROFILE_EXPIRY_UNKNOWN');
    await expect(
      renewal.chooseName(
        { ownerId: 'o', connectionId: 'c', generation: 1 },
        'own',
        'bundle',
        async () => [
          {
            id: 'bad',
            attributes: { name: 'foreign', expirationDate: new Date(9000).toISOString() },
          },
        ],
        async () => {},
      ),
    ).rejects.toThrow('PROFILE_RESOURCE_MISMATCH');
    expect((await db.query('SELECT id FROM provisioning_operations')).rows).toHaveLength(0);
  } finally {
    await db.close();
  }
});
