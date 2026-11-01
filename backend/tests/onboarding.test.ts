import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import {
  parseTeamKey,
  suggestedKeyId,
  AppleOnboarding,
} from '../packages/core/src/apple/onboarding';
const fixture = () =>
  Buffer.from(
    generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({
      type: 'pkcs8',
      format: 'pem',
    }),
  );
describe('Team onboarding', () => {
  it('derives editable filename ID and validates key', () => {
    expect(suggestedKeyId('AuthKey_ABCDEFGHIJ.p8')).toBe('ABCDEFGHIJ');
    expect(
      parseTeamKey({
        filename: 'AuthKey_ABCDEFGHIJ.p8',
        keyId: '0123456789',
        issuerId: '01234567-89ab-cdef-0123-456789abcdef',
        p8: fixture(),
      }).keyId,
    ).toBe('0123456789');
  });
  it('rejects individual key', () =>
    expect(() =>
      parseTeamKey({ filename: 'x', keyType: 'individual', issuerId: 'x', p8: fixture() }),
    ).toThrow('TEAM_KEY_REQUIRED'));
  it('fails unproven Team and wipes secret', async () => {
    const p8 = fixture();
    let action = '';
    const port = {
      begin: async () => ({ id: 'c', generation: 1 }),
      seal: async () => 's',
      stageCredentials: async () => true,
      commit: async () => true,
      discard: async () => {},
      actionRequired: async (_o: string, _c: string, _g: number, r: string) => {
        action = r;
      },
    };
    await expect(
      new AppleOnboarding(
        port,
        async () => ({ teamId: 'ABCDEFGHIJ', source: 'apple-api-certificate', verified: false }),
        () => 1,
      ).connect('o', {
        filename: 'AuthKey_ABCDEFGHIJ.p8',
        issuerId: '01234567-89ab-cdef-0123-456789abcdef',
        p8,
      }),
    ).rejects.toThrow('TEAM_PROOF_REQUIRED');
    expect(action).toBe('TEAM_PROOF_REQUIRED');
    expect(p8.every((x) => x === 0)).toBe(true);
  });
});
import {
  TeamBootstrap,
  DatabaseOnboardingPort,
  type BootstrapPort,
} from '../packages/core/src/apple/onboarding';
import { createDatabase } from './helpers/database';
it('requires disconnecting an occupied binding before reconnecting', async () => {
  const db = await createDatabase();
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','o@test.example',1)");
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
    );
    await db.query(
      "INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag) VALUES('s','o','c','p8','wrapped','nonce','cipher','tag')",
    );
    await db.query(
      "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
    );
    const port = new DatabaseOnboardingPort(db, {} as never, () => 7);
    await expect(port.begin('o')).rejects.toThrow('APPLE_CONNECTION_EXISTS');
    expect((await db.query('SELECT deleted_at FROM secrets')).rows).toEqual([{ deleted_at: null }]);
    await expect(port.begin('missing')).rejects.toThrow('USER_UNAVAILABLE');
  } finally {
    await db.close();
  }
});
it('bootstrap refuses stale lease before identity work', async () => {
  let generated = false;
  const port = {
    acquire: async () => ({
      ownerId: 'o',
      connectionId: 'c',
      generation: 1,
      nonce: 'n',
      expiresAt: 0,
    }),
    prepareIdentity: async () => {
      generated = true;
    },
  } as unknown as BootstrapPort;
  await expect(new TeamBootstrap(port, () => 1).prove('o', 'c', 1)).rejects.toThrow(
    'STALE_BOOTSTRAP_LEASE',
  );
  expect(generated).toBe(false);
});
it('bootstrap persists identity before mutation and unknown result does not retry', async () => {
  const events: string[] = [];
  const port = {
    acquire: async () => ({
      ownerId: 'o',
      connectionId: 'c',
      generation: 1,
      nonce: 'n',
      expiresAt: 100,
    }),
    assertCurrent: async () => {},
    prepareIdentity: async () => {
      events.push('persist');
      return {
        secretRef: 's',
        csr: '-----BEGIN CERTIFICATE REQUEST-----\nsynthetic',
        spkiSha256: 'a'.repeat(64),
      };
    },
    claimCertificate: async () => 'new' as const,
    findCertificates: async () => [],
    createCertificate: async () => {
      events.push('POST');
      throw Error('timeout');
    },
    markUnknown: async () => {
      events.push('unknown');
    },
    commitIdentity: async () => true,
  };
  await expect(new TeamBootstrap(port, () => 1).prove('o', 'c', 1)).rejects.toThrow(
    'RESOURCE_RECONCILIATION_REQUIRED',
  );
  expect(events).toEqual(['persist', 'POST', 'unknown']);
  await expect(
    new TeamBootstrap(
      { ...port, claimCertificate: async () => 'reconcile' as const },
      () => 1,
    ).prove('o', 'c', 1),
  ).rejects.toThrow('RESOURCE_RECONCILIATION_REQUIRED');
  expect(events.filter((x) => x === 'POST')).toHaveLength(1);
});
it('retains encrypted staged P8 only for bootstrap-required proof', async () => {
  const events: string[] = [];
  const port = {
    begin: async () => ({ id: 'c', generation: 1 }),
    seal: async () => {
      events.push('sealed');
      return 's';
    },
    stageCredentials: async () => {
      events.push('staged');
      return true;
    },
    commit: async () => true,
    discard: async () => {
      events.push('discard');
    },
    actionRequired: async () => {
      events.push('action_required');
    },
  };
  const input = () => ({
    filename: 'AuthKey_ABCDEFGHIJ.p8',
    issuerId: '01234567-89ab-cdef-0123-456789abcdef',
    p8: fixture(),
  });
  await expect(
    new AppleOnboarding(
      port,
      async () => {
        events.push('validate');
        throw new (await import('../packages/core/src/application/service')).Failure(
          'TEAM_PROOF_REQUIRED',
          409,
        );
      },
      () => 1,
    ).connect('o', input()),
  ).rejects.toThrow('TEAM_PROOF_REQUIRED');
  expect(events).toEqual(['sealed', 'staged', 'validate', 'action_required']);
  events.length = 0;
  await expect(
    new AppleOnboarding(
      port,
      async () => {
        throw new (await import('../packages/core/src/application/service')).Failure(
          'APPLE_ACCESS_ACTION_REQUIRED',
          403,
        );
      },
      () => 1,
    ).connect('o', input()),
  ).rejects.toThrow('APPLE_ACCESS_ACTION_REQUIRED');
  expect(events).toEqual(['sealed', 'staged', 'discard', 'action_required']);
});
it('rejects stale proof commit and removes staged credential', async () => {
  let deleted = false;
  const port = {
    begin: async () => ({ id: 'c', generation: 1 }),
    seal: async () => 's',
    stageCredentials: async () => true,
    commit: async () => false,
    discard: async () => {
      deleted = true;
    },
    actionRequired: async () => {},
  };
  await expect(
    new AppleOnboarding(
      port,
      async () => ({ teamId: 'ABCDEFGHIJ', source: 'apple-api-certificate', verified: true }),
      () => 1,
    ).connect('o', {
      filename: 'AuthKey_ABCDEFGHIJ.p8',
      issuerId: '01234567-89ab-cdef-0123-456789abcdef',
      p8: fixture(),
    }),
  ).rejects.toThrow('CONNECTION_CHANGED');
  expect(deleted).toBe(true);
});
