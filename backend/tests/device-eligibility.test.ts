import { ownAuthority } from './helpers/seed-authority';
import { it, expect } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { createDatabase } from './helpers/database';
import {
  DeviceEligibilityProbe,
  type DeviceEligibilityApi,
  type ControlProfileVerifier,
  type ControlResource,
} from '../packages/core/src/devices/eligibility';
import { hash } from '../packages/core/src/shared/index';
const binding = { ownerId: 'o', connectionOwnerId: 'o', connectionId: 'c', generation: 1 },
  udid = 'A'.repeat(40);
async function fixture() {
  const temp = mkdtempSync(join(tmpdir(), 'isign-eligibility-fixture-'));
  let pem: string;
  try {
    execFileSync(
      'openssl',
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        join(temp, 'key'),
        '-out',
        join(temp, 'cert'),
        '-subj',
        '/CN=Synthetic fixture/OU=ABCDEFGHIJ',
        '-days',
        '1',
      ],
      { stdio: 'ignore' },
    );
    pem = readFileSync(join(temp, 'cert'), 'utf8');
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
  const cert = new X509Certificate(pem);
  const now = Date.parse(cert.validFrom) + 1000;
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','o@test.example',1)");
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','ABCDEFGHIJ','ready','asc')",
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,name,status,udid,udid_hash,connection_generation,enrollment_verified_at,enrollment_cms_sha256) VALUES('d','o','c','phone','collected',$1,$2,1,1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
    [udid, hash(udid)],
  );
  await db.query(
    "INSERT INTO secrets(id,owner_id,connection_id,purpose,wrapped_key,nonce,ciphertext,tag,generation) VALUES('s','o','c','distribution-key','w','n','c','t',1)",
  );
  await db.query(
    "INSERT INTO bootstrap_operations(owner_id,connection_id,generation,nonce,expires_at,identity,certificate_state,certificate) VALUES('o','c',1,'n',$1,$2,'committed',$3)",
    [
      now + 10000,
      JSON.stringify({
        secretRef: 's',
        spkiSha256: createHash('sha256')
          .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
          .digest('hex'),
      }),
      JSON.stringify({
        id: 'cert',
        pem,
        teamId: 'ABCDEFGHIJ',
        expiresAt: Date.parse(cert.validTo),
      }),
    ],
  );
  let bundles: ControlResource[] = [],
    profiles: ControlResource[] = [],
    posts = 0;
  const api: DeviceEligibilityApi = {
    rawDevice: async () => ({ id: 'apple', status: 'ENABLED' }),
    findBundles: async () => bundles,
    bundle: async (identifier) => {
      posts++;
      const row = { id: 'bundle', attributes: { identifier } };
      bundles = [row];
      return row;
    },
    findProfiles: async (_bundle, name) => profiles.filter((p) => p.attributes.name === name),
    profile: async (request) => {
      posts++;
      const row = {
        id: 'profile',
        attributes: {
          name: request.name,
          profileState: 'ACTIVE',
          expirationDate: new Date(now + 10000).toISOString(),
          profileContent: Buffer.from('synthetic CMS fixture').toString('base64'),
        },
      };
      profiles = [row];
      return row;
    },
  };
  const verify: ControlProfileVerifier = async (input) => ({
    cmsSha256: input.cmsSha256,
    teamId: input.expected.teamId,
    bundleId: input.expected.bundleId,
    deviceUdids: [input.expected.udid],
    certificateSha256s: [input.expected.certificateSha256],
    expiresAt: now + 10000,
    profileType: 'ad-hoc',
  });
  await ownAuthority(db);
  return { db, now, api, verify, posts: () => posts };
}
it('breaks readiness cycle with owned control profile, then reconciles without further POST', async () => {
  const f = await fixture();
  try {
    const probe = new DeviceEligibilityProbe(
      f.db,
      () => f.now,
      async () => f.api,
      f.verify,
    );
    expect(await probe.check(binding, 'apple', udid)).toEqual({ eligible: true });
    expect(await probe.check(binding, 'apple', udid)).toEqual({ eligible: true });
    expect(f.posts()).toBe(2);
    expect((await f.db.query('SELECT * FROM provisioning_operations')).rows).toHaveLength(2);
  } finally {
    await f.db.close();
  }
});
it('does not accept CMS flags, wrong UDID, expired profile or absent trusted verifier', async () => {
  const f = await fixture();
  try {
    await expect(
      new DeviceEligibilityProbe(
        f.db,
        () => f.now,
        async () => f.api,
      ).check(binding, 'apple', udid),
    ).rejects.toThrow('PROFILE_CMS_VERIFIER_UNAVAILABLE');
    const wrong: ControlProfileVerifier = async (i) => ({
      ...(await f.verify(i)),
      deviceUdids: ['B'.repeat(40)],
    });
    await expect(
      new DeviceEligibilityProbe(
        f.db,
        () => f.now,
        async () => f.api,
        wrong,
      ).check(binding, 'apple', udid),
    ).rejects.toThrow('CONTROL_PROFILE_PROOF_MISMATCH');
    const expired: ControlProfileVerifier = async (i) => ({
      ...(await f.verify(i)),
      expiresAt: f.now,
    });
    await expect(
      new DeviceEligibilityProbe(
        f.db,
        () => f.now,
        async () => f.api,
        expired,
      ).check(binding, 'apple', udid),
    ).rejects.toThrow('CONTROL_PROFILE_PROOF_MISMATCH');
  } finally {
    await f.db.close();
  }
});
it('unknown certificate/profile mutation reconciles before any repeat POST', async () => {
  const f = await fixture();
  try {
    let profilePosts = 0;
    const api = {
      ...f.api,
      profile: async () => {
        profilePosts++;
        throw Error('timeout');
      },
    };
    const probe = new DeviceEligibilityProbe(
      f.db,
      () => f.now,
      async () => api,
      f.verify,
    );
    await expect(probe.check(binding, 'apple', udid)).rejects.toThrow(
      'RESOURCE_RECONCILIATION_REQUIRED',
    );
    await expect(probe.check(binding, 'apple', udid)).rejects.toThrow(
      'RESOURCE_RECONCILIATION_REQUIRED',
    );
    expect(profilePosts).toBe(1);
    expect(
      (
        await f.db.query<{ state: string }>(
          "SELECT state FROM provisioning_operations WHERE kind='eligibility-profile'",
        )
      ).rows[0].state,
    ).toBe('unknown');
  } finally {
    await f.db.close();
  }
});
it('rechecks generation after guest evidence and binds owner/device', async () => {
  const f = await fixture();
  try {
    const verifier: ControlProfileVerifier = async (input) => {
      await f.db.query("UPDATE connections SET generation=2 WHERE id='c'");
      return f.verify(input);
    };
    await expect(
      new DeviceEligibilityProbe(
        f.db,
        () => f.now,
        async () => f.api,
        verifier,
      ).check(binding, 'apple', udid),
    ).rejects.toThrow('APPLE_ACCESS_UNAVAILABLE');
    await expect(
      new DeviceEligibilityProbe(
        f.db,
        () => f.now,
        async () => f.api,
        f.verify,
      ).check({ ...binding, ownerId: 'foreign' }, 'apple', udid),
    ).rejects.toThrow('APPLE_ACCESS_UNAVAILABLE');
  } finally {
    await f.db.close();
  }
});
it('requires owned persisted distribution identity and does not provision a disabled Apple device', async () => {
  const f = await fixture();
  try {
    const api = { ...f.api, rawDevice: async () => ({ id: 'apple', status: 'DISABLED' }) };
    expect(
      await new DeviceEligibilityProbe(
        f.db,
        () => f.now,
        async () => api,
        f.verify,
      ).check(binding, 'apple', udid),
    ).toEqual({ ineligible: true });
    expect(f.posts()).toBe(0);
    await f.db.query("UPDATE secrets SET deleted_at=1 WHERE id='s'");
    await expect(
      new DeviceEligibilityProbe(
        f.db,
        () => f.now,
        async () => f.api,
        f.verify,
      ).check(binding, 'apple', udid),
    ).rejects.toThrow('CERTIFICATE_REQUIRED');
  } finally {
    await f.db.close();
  }
});
import { Failure } from '../packages/core/src/shared/index';
it('reconciles before retrying an explicitly rejected profile POST', async () => {
  const f = await fixture();
  try {
    let attempts = 0;
    const api = {
      ...f.api,
      profile: async (input: Parameters<DeviceEligibilityApi['profile']>[0]) => {
        attempts++;
        if (attempts === 1) throw new Failure('APPLE_OPERATION_REJECTED', 409);
        return f.api.profile(input);
      },
    };
    const probe = new DeviceEligibilityProbe(
      f.db,
      () => f.now,
      async () => api,
      f.verify,
    );
    await expect(probe.check(binding, 'apple', udid)).rejects.toThrow('APPLE_OPERATION_REJECTED');
    expect(await probe.check(binding, 'apple', udid)).toEqual({ eligible: true });
    expect(attempts).toBe(2);
  } finally {
    await f.db.close();
  }
});
it('advances an expired control profile revision rather than permanently reusing old CMS', async () => {
  const f = await fixture();
  try {
    const names: string[] = [];
    let oldName = '';
    const api = {
      ...f.api,
      findProfiles: async (bundle: string, name: string) => {
        const rows = await f.api.findProfiles(bundle, name);
        return rows.map((row) =>
          row.attributes.name === oldName
            ? {
                ...row,
                attributes: { ...row.attributes, expirationDate: new Date(f.now).toISOString() },
              }
            : row,
        );
      },
      profile: async (input: Parameters<DeviceEligibilityApi['profile']>[0]) => {
        names.push(input.name);
        return f.api.profile(input);
      },
    };
    const probe = new DeviceEligibilityProbe(
      f.db,
      () => f.now,
      async () => api,
      f.verify,
    );
    expect(await probe.check(binding, 'apple', udid)).toEqual({ eligible: true });
    oldName = names[0];
    expect(await probe.check(binding, 'apple', udid)).toEqual({ eligible: true });
    expect(names).toEqual([oldName, oldName + '-r1']);
    expect(f.posts()).toBe(3);
  } finally {
    await f.db.close();
  }
});
