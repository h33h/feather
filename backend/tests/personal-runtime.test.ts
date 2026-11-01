import { expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { createDatabase } from './helpers/database';
import { Service } from '../packages/core/src/application/service';
import { CatalogRegistry } from '../packages/core/src/catalog/registry';
import { InstallationHistory } from '../packages/core/src/library/installation-history';
import { handleSession } from '../server/http/session';
import type { AuthenticatedContext } from '../server/http/context';
it('reads a lightweight session without creating catalogs or reconciling devices', async () => {
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1)");
  const app = {
    db,
    service: new Service(db, { now: () => 1000 }),
    catalogs: new CatalogRegistry(db, () => 1000),
    collections: { reconcileOwner: async () => {}, list: async () => [] },
    sharing: { list: async () => [] },
    capabilities: {
      runner: false,
      appleOnboarding: true,
      bootstrap: false,
      deviceEnrollment: true,
    },
  };
  const context = {
    request: new NextRequest('http://127.0.0.1:3000/api/session', {
      headers: { cookie: 'isign-csrf=csrf' },
    }),
    target: 'session',
    app,
    raw: '',
    csrf: '',
    owner: 'o',
    session: {
      ownerId: 'o',
      role: 'user',
      loginName: 'owner',
      publicProfileId: 'public',
      verifiedAt: 1000,
    },
    history: new InstallationHistory(db, () => 1000),
    uploadAllowed: async () => false,
    requireUpload: async () => {},
  } as unknown as AuthenticatedContext;
  const reply = await handleSession(context);
  const value = await reply!.json();
  expect(value).toMatchObject({
    csrf: 'csrf',
    profile: { id: 'o', loginName: 'owner', role: 'user' },
  });
  for (const key of ['jobs', 'uploads', 'artifacts', 'history', 'sources', 'collectedDevices'])
    expect(value).not.toHaveProperty(key);
  expect((await db.query('SELECT id FROM sources')).rows).toHaveLength(0);
});
