import { it, expect } from 'vitest';
import { AppleProvisioningApi } from '../packages/core/src/apple/provisioning-client';
import { Failure } from '../packages/core/src/shared/index';
it('finding an existing Apple device does not fail because its signing certificate is missing', async () => {
  const api = new AppleProvisioningApi(
    {
      request: async (method) => {
        if (method !== 'GET') throw Error('UNEXPECTED_APPLE_MUTATION');
        return {
          data: [
            {
              id: 'device',
              type: 'devices',
              attributes: { udid: 'A'.repeat(40), status: 'ENABLED', platform: 'IOS' },
            },
          ],
        };
      },
    },
    () => 1,
    async () => {
      throw new Failure('CERTIFICATE_REQUIRED', 409);
    },
  );
  expect(await api.find('A'.repeat(40))).toEqual([
    { id: 'device', status: 'ENABLED', certificateRequired: true },
  ]);
});
it('device lookup keeps rejecting an invalid eligibility proof', async () => {
  const api = new AppleProvisioningApi(
    {
      request: async () => ({
        data: [
          {
            id: 'device',
            type: 'devices',
            attributes: { udid: 'A'.repeat(40), status: 'ENABLED', platform: 'IOS' },
          },
        ],
      }),
    },
    () => 1,
    async () => {
      throw new Failure('CONTROL_PROFILE_PROOF_MISMATCH', 409);
    },
  );
  await expect(api.find('A'.repeat(40))).rejects.toThrow('CONTROL_PROFILE_PROOF_MISMATCH');
});
it('uses JSON API IOS Ad Hoc profile relationships', async () => {
  let captured: unknown;
  const api = new AppleProvisioningApi(
    {
      request: async (_method, _path, body) => {
        captured = body;
        return { data: { id: 'p', type: 'profiles', attributes: {} } };
      },
    },
    () => 1,
  );
  await api.profile({ name: 'app', bundleId: 'b', certificateIds: ['c'], deviceIds: ['d'] });
  expect(captured).toEqual({
    data: {
      type: 'profiles',
      attributes: { name: 'app', profileType: 'IOS_APP_ADHOC' },
      relationships: {
        bundleId: { data: { type: 'bundleIds', id: 'b' } },
        certificates: { data: [{ type: 'certificates', id: 'c' }] },
        devices: { data: [{ type: 'devices', id: 'd' }] },
      },
    },
  });
});
it('requires actual public certificate Team proof', async () => {
  const api = new AppleProvisioningApi({ request: async () => ({ data: [] }) }, () => 1);
  await expect(api.teamProof()).rejects.toThrow('TEAM_PROOF_REQUIRED');
});
it('Apple ENABLED is not fabricated profile eligibility', async () => {
  const api = new AppleProvisioningApi(
    {
      request: async () => ({
        data: [
          { id: 'd', type: 'devices', attributes: { udid: 'A'.repeat(40), status: 'ENABLED' } },
        ],
      }),
    },
    () => 1,
  );
  expect(await api.find('A'.repeat(40))).toEqual([{ id: 'd', status: 'ENABLED' }]);
  const eligible = new AppleProvisioningApi(
    {
      request: async () => ({
        data: [
          { id: 'd', type: 'devices', attributes: { udid: 'A'.repeat(40), status: 'ENABLED' } },
        ],
      }),
    },
    () => 1,
    async () => ({ eligible: true }),
  );
  expect((await eligible.find('A'.repeat(40)))[0].eligible).toBe(true);
});
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
it('reconciles only the persisted SPKI public certificate with current Team OU', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'isign-synthetic-certificate-'));
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
        join(directory, 'synthetic.key'),
        '-out',
        join(directory, 'synthetic.crt'),
        '-subj',
        '/CN=Synthetic fixture/OU=ABCDEFGHIJ',
        '-days',
        '1',
      ],
      { stdio: 'ignore' },
    );
    const pem = readFileSync(join(directory, 'synthetic.crt'), 'utf8');
    const cert = new X509Certificate(pem);
    const digest = createHash('sha256')
      .update(cert.publicKey.export({ type: 'spki', format: 'der' }))
      .digest('hex');
    let now = Date.parse(cert.validFrom) + 1000;
    const api = new AppleProvisioningApi(
      {
        request: async () => ({
          data: [
            {
              id: 'synthetic',
              type: 'certificates',
              attributes: { certificateContent: Buffer.from(pem).toString('base64') },
            },
            { id: 'invalid', type: 'certificates', attributes: { certificateContent: 'garbage' } },
          ],
        }),
      },
      () => now,
    );
    expect(await api.findCertificates(digest)).toEqual([
      { id: 'synthetic', certificate: cert.toString() },
    ]);
    expect(await api.findCertificates('a'.repeat(64))).toEqual([]);
    now = Date.parse(cert.validTo) + 1;
    expect(await api.findCertificates(digest)).toEqual([]);
    await expect(api.findCertificates('bad')).rejects.toThrow('INVALID_PUBLIC_KEY_DIGEST');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

for (const identifier of ['*', 'com.example.*'])
  it('creates a terminal wildcard App ID scope ' + identifier, async () => {
    let captured: unknown;
    const api = new AppleProvisioningApi(
      {
        request: async (method, _path, body) => {
          if (method === 'GET') return { data: [] };
          captured = body;
          return { data: { id: 'scope', type: 'bundleIds', attributes: { identifier } } };
        },
      },
      () => 1,
    );
    expect((await api.bundle(identifier, 'Wildcard')).attributes.identifier).toBe(identifier);
    expect(captured).toMatchObject({ data: { attributes: { identifier, platform: 'IOS' } } });
  });
for (const identifier of ['com.*.example', 'com.example.**', '*.example', 'com..example', 'single'])
  it('rejects malformed App ID scope ' + identifier, async () => {
    const api = new AppleProvisioningApi(
      {
        request: async () => {
          throw Error('unexpected API access');
        },
      },
      () => 1,
    );
    await expect(api.bundle(identifier, 'Bad')).rejects.toThrow('INVALID_BUNDLE_ID');
  });
