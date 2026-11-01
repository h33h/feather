import { test, expect } from 'vitest';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createDatabase } from './helpers/database';
import { PersonalAuth } from '../packages/core/src/auth/passkeys';
const b64 = (b: Buffer) => b.toString('base64url');
function cbor(value: unknown): Buffer {
  const head = (major: number, n: number) =>
    n < 24
      ? Buffer.from([major * 32 + n])
      : n < 256
        ? Buffer.from([major * 32 + 24, n])
        : Buffer.from([major * 32 + 25, n >> 8, n & 255]);
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') {
    const b = Buffer.from(value);
    return Buffer.concat([head(3, b.length), b]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof Map)
    return Buffer.concat([
      head(5, value.size),
      ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)]),
    ]);
  throw new Error('test CBOR value');
}
const origin = 'https://isign.cloudnodex.ru';
function fixture(
  challenge: string,
  type: 'webauthn.create' | 'webauthn.get',
  key: ReturnType<typeof generateKeyPairSync>,
  credential: Buffer,
  counter = 0,
  overrides: { origin?: string; uv?: boolean } = {},
) {
  const client = Buffer.from(
      JSON.stringify({ type, challenge, origin: overrides.origin ?? origin, crossOrigin: false }),
    ),
    auth = Buffer.concat([
      createHash('sha256').update('isign.cloudnodex.ru').digest(),
      Buffer.from([
        type === 'webauthn.create'
          ? overrides.uv === false
            ? 65
            : 69
          : overrides.uv === false
            ? 1
            : 5,
      ]),
      Buffer.from([0, 0, 0, counter]),
    ]);
  const common = {
    id: b64(credential),
    rawId: b64(credential),
    type: 'public-key' as const,
    clientExtensionResults: {},
    authenticatorAttachment: 'platform' as const,
  };
  if (type === 'webauthn.get')
    return {
      ...common,
      response: {
        clientDataJSON: b64(client),
        authenticatorData: b64(auth),
        signature: b64(
          sign(
            'sha256',
            Buffer.concat([auth, createHash('sha256').update(client).digest()]),
            key.privateKey,
          ),
        ),
        userHandle: null,
      },
    };
  const jwk = key.publicKey.export({ format: 'jwk' });
  const cose = cbor(
    new Map<unknown, unknown>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x!, 'base64url')],
      [-3, Buffer.from(jwk.y!, 'base64url')],
    ]),
  );
  const len = Buffer.alloc(2);
  len.writeUInt16BE(credential.length);
  return {
    ...common,
    response: {
      clientDataJSON: b64(client),
      attestationObject: b64(
        cbor(
          new Map<unknown, unknown>([
            ['fmt', 'none'],
            ['attStmt', new Map()],
            ['authData', Buffer.concat([auth, Buffer.alloc(16), len, credential, cose])],
          ]),
        ),
      ),
      transports: ['internal'],
    },
  };
}
test('invite-only real WebAuthn enrollment/login reject replay and recovery revokes access', async () => {
  const db = await createDatabase();
  try {
    const auth = new PersonalAuth(db, origin, () => 1000),
      invite = await auth.invite('owner');
    const reg = await auth.registrationOptions(invite.token);
    const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      credential = randomBytes(32);
    const result = await auth.register(
      reg.requestId,
      fixture(reg.options.challenge, 'webauthn.create', key, credential) as never,
    );
    expect(result).not.toHaveProperty('recoveryCodes');
    await expect(
      auth.register(
        reg.requestId,
        fixture(reg.options.challenge, 'webauthn.create', key, credential) as never,
      ),
    ).rejects.toThrow();
    const login = await auth.authenticationOptions();
    const session = await auth.authenticate(
      login.requestId,
      fixture(login.options.challenge, 'webauthn.get', key, credential, 1) as never,
    );
    expect(session.ownerId).toBe(invite.ownerId);
    await expect(
      auth.authenticate(
        login.requestId,
        fixture(login.options.challenge, 'webauthn.get', key, credential, 1) as never,
      ),
    ).rejects.toThrow();
    const recovery = await auth.operatorReinvite(invite.ownerId);
    expect(recovery.token).toHaveLength(43);
    expect((await db.query('SELECT * FROM sessions')).rows).toHaveLength(0);
    expect((await db.query('SELECT * FROM passkeys')).rows).toHaveLength(0);
    await auth.invite('second');
    await auth.invite('third');
    await expect(auth.invite('fourth')).resolves.toHaveProperty('ownerId');
  } finally {
    await db.close();
  }
});

async function harness() {
  const db = await createDatabase();
  const auth = new PersonalAuth(db, origin, () => 1000),
    invite = await auth.invite('owner'),
    key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    credential = randomBytes(32);
  return { db, auth, invite, key, credential };
}
for (const kind of ['origin', 'challenge', 'uv'] as const) {
  test('registration rejects wrong ' + kind, async () => {
    const h = await harness();
    try {
      const reg = await h.auth.registrationOptions(h.invite.token);
      const response = fixture(
        kind === 'challenge' ? 'wrong' : reg.options.challenge,
        'webauthn.create',
        h.key,
        h.credential,
        0,
        { origin: kind === 'origin' ? 'https://attacker.invalid' : origin, uv: kind !== 'uv' },
      );
      await expect(h.auth.register(reg.requestId, response as never)).rejects.toThrow(
        'PASSKEY_AUTH_FAILED',
      );
      expect((await h.db.query('SELECT * FROM passkeys')).rows).toHaveLength(0);
    } finally {
      await h.db.close();
    }
  });
  test('authentication rejects wrong ' + kind, async () => {
    const h = await harness();
    try {
      const reg = await h.auth.registrationOptions(h.invite.token);
      await h.auth.register(
        reg.requestId,
        fixture(reg.options.challenge, 'webauthn.create', h.key, h.credential) as never,
      );
      const login = await h.auth.authenticationOptions();
      const response = fixture(
        kind === 'challenge' ? 'wrong' : login.options.challenge,
        'webauthn.get',
        h.key,
        h.credential,
        1,
        { origin: kind === 'origin' ? 'https://attacker.invalid' : origin, uv: kind !== 'uv' },
      );
      await expect(h.auth.authenticate(login.requestId, response as never)).rejects.toThrow(
        'PASSKEY_AUTH_FAILED',
      );
    } finally {
      await h.db.close();
    }
  });
}
test('fresh authentication rotates sessions and add-passkey challenge is bound to the exact fresh session', async () => {
  const h = await harness();
  try {
    const reg = await h.auth.registrationOptions(h.invite.token),
      first = await h.auth.register(
        reg.requestId,
        fixture(reg.options.challenge, 'webauthn.create', h.key, h.credential) as never,
      );
    const login = await h.auth.authenticationOptions(),
      second = await h.auth.authenticate(
        login.requestId,
        fixture(login.options.challenge, 'webauthn.get', h.key, h.credential, 1) as never,
      );
    const fresh = await h.auth.authenticationOptions(first.ownerId, first.token);
    await expect(
      h.auth.authenticate(
        fresh.requestId,
        fixture(fresh.options.challenge, 'webauthn.get', h.key, h.credential, 2) as never,
        second.token,
      ),
    ).rejects.toThrow();
    const add = await h.auth.addOptions(first.ownerId, first.token),
      newKey = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
      newId = randomBytes(32);
    await expect(
      h.auth.register(
        add.requestId,
        fixture(add.options.challenge, 'webauthn.create', newKey, newId) as never,
        second.token,
      ),
    ).rejects.toThrow();
    const next = await h.auth.authenticationOptions(first.ownerId, first.token),
      rotated = await h.auth.authenticate(
        next.requestId,
        fixture(next.options.challenge, 'webauthn.get', h.key, h.credential, 2) as never,
        first.token,
      );
    expect(rotated.token).not.toBe(first.token);
    const validAdd = await h.auth.addOptions(rotated.ownerId, rotated.token);
    await h.auth.register(
      validAdd.requestId,
      fixture(validAdd.options.challenge, 'webauthn.create', newKey, newId) as never,
      rotated.token,
    );
    expect((await h.db.query('SELECT id FROM passkeys')).rows).toHaveLength(2);
  } finally {
    await h.db.close();
  }
});
