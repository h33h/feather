import { expect, it } from 'vitest';
import { createDatabase } from './helpers/database';
import { loginFixture } from './helpers/login';
import { hash, id, token } from '../packages/core/src/shared';
import { NativeSessions } from '../packages/core/src/auth/native-sessions';
import { NativeApplication } from '../packages/core/src/application/native-application';

async function fixture() {
  const db = await createDatabase();
  const now = 1000000;
  const owner = await loginFixture(db, 'native-owner', now);
  const raw = token(),
    sessionId = id();
  await db.query(
    'INSERT INTO native_sessions(id,owner_id,access_hash,verified_at,expires_at,refresh_expires_at) VALUES($1,$2,$3,$4,$5,$6)',
    [sessionId, owner.ownerId, hash(raw), now, now + 900000, now + 2592000000],
  );
  const auth = new NativeSessions(db, {
    origin: 'https://isign.example.test',
    callback: 'isign-feather://auth/callback',
    now: () => now,
  });
  const events: string[] = [];
  const ports = {
    auth,
    queries: {
      apple: async (actor: string) => ({ connection: { id: actor }, uploadAllowed: true }),
      devices: async () => [],
    },
    sharing: {
      list: async () => [],
      share: async (actor: string) => {
        events.push(actor);
        return { ok: true };
      },
      revoke: async () => ({ ok: true }),
    },
    assets: {
      ensure: async (actor: string) => {
        events.push(actor);
        return { state: 'ready' };
      },
      bundle: async () => ({ p12: 'private-material' }),
      profiles: async () => ({ state: 'ready', profiles: [] }),
    },
    catalog: {
      list: async () => ({ sources: [] }),
      download: async () => ({ url: 'https://files.example/app.ipa' }),
    },
    admin: {
      invite: async (actor: string, name: string) => {
        events.push(actor + ':' + name);
        return { token: 'invite' };
      },
    },
  };
  return {
    db,
    now,
    owner,
    raw,
    sessionId,
    events,
    ports,
    app: new NativeApplication(ports as never),
  };
}

it('native reads use the authenticated owner and never a supplied actor', async () => {
  const f = await fixture();
  const result = await f.app.view(f.raw, { kind: 'apple' });
  expect(result).toMatchObject({ connection: { id: f.owner.ownerId }, shares: [] });
  await expect(f.app.view('wrong', { kind: 'apple' })).rejects.toThrow('UNAUTHENTICATED');
});
it('a native logout during catalog work prevents private query and descriptor delivery', async () => {
  const f = await fixture();
  for (const action of ['query', 'download']) {
    await f.db.query('UPDATE native_sessions SET revoked_at=NULL WHERE id=$1', [f.sessionId]);
    let start!: () => void, release!: () => void;
    const begun = new Promise<void>((r) => {
      start = r;
    });
    const gate = new Promise<void>((r) => {
      release = r;
    });
    f.ports.catalog.list = async () => {
      start();
      await gate;
      return { sources: [] };
    };
    f.ports.catalog.download = async () => {
      start();
      await gate;
      return { url: 'https://files.example/app.ipa' };
    };
    const pending =
      action === 'query'
        ? f.app.view(f.raw, { kind: 'sources' })
        : f.app.command(f.raw, {
            kind: 'source.download',
            sourceId: 's',
            releaseId: 'r',
            snapshot: 'snap',
          });
    await Promise.race([begun, pending]);
    await f.db.query('UPDATE native_sessions SET revoked_at=$2 WHERE id=$1', [f.sessionId, f.now]);
    release();
    await expect(pending).rejects.toThrow('UNAUTHENTICATED');
  }
});
it('sensitive native commands require current fresh passkey proof', async () => {
  const f = await fixture();
  await f.db.query('UPDATE native_sessions SET verified_at=$2 WHERE id=$1', [
    f.sessionId,
    f.now - 600000,
  ]);
  await expect(
    f.app.command(f.raw, { kind: 'apple.share', profileId: 'profile_x' }),
  ).rejects.toThrow('FRESH_AUTH_REQUIRED');
  await expect(f.app.command(f.raw, { kind: 'signing.bundle' })).rejects.toThrow(
    'FRESH_AUTH_REQUIRED',
  );
  expect(f.events).toEqual([]);
  await expect(
    f.app.command(f.raw, { kind: 'signing.ensure', retry: false }),
  ).resolves.toMatchObject({ state: 'ready' });
  await expect(f.app.command(f.raw, { kind: 'signing.ensure', retry: true })).rejects.toThrow(
    'FRESH_AUTH_REQUIRED',
  );
});
it('native admin uses the current database role and fresh identity', async () => {
  const f = await fixture();
  await expect(f.app.command(f.raw, { kind: 'admin.invite', name: 'guest' })).rejects.toThrow(
    'ADMIN_REQUIRED',
  );
  expect(f.events).toEqual([]);
  await f.db.query("UPDATE users SET role='admin' WHERE id=$1", [f.owner.ownerId]);
  await expect(
    f.app.command(f.raw, { kind: 'admin.invite', name: 'guest' }),
  ).resolves.toMatchObject({ token: 'invite' });
  expect(f.events).toEqual([f.owner.ownerId + ':guest']);
});
it('a native logout during material preparation prevents P12 delivery', async () => {
  const f = await fixture();
  let started!: () => void, release!: () => void;
  const begun = new Promise<void>((r) => {
    started = r;
  });
  const gate = new Promise<void>((r) => {
    release = r;
  });
  f.ports.assets.bundle = async () => {
    started();
    await gate;
    return { p12: 'private-material' };
  };
  const pending = f.app.command(f.raw, { kind: 'signing.bundle' });
  await Promise.race([begun, pending]);
  await f.db.query('UPDATE native_sessions SET revoked_at=$2 WHERE id=$1', [f.sessionId, f.now]);
  release();
  await expect(pending).rejects.toThrow('UNAUTHENTICATED');
});
