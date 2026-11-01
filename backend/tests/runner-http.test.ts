import { createHmac } from 'node:crypto';
import { expect, it } from 'vitest';
import { canonicalReport } from '../packages/core/src/shared/canonical-json';
const key = Buffer.alloc(32, 1);
async function* bytes(value: unknown) {
  yield Buffer.from(JSON.stringify(value));
}
const input = {
  ownerId: 'o',
  jobId: 'j',
  launchNonce: 'n'.repeat(43),
  signal: new AbortController().signal,
  maxRuntimeMs: 1000,
  maxInputBytes: 10,
  maxUnpackedBytes: 20,
  maxEntries: 10,
};
it('bootstrap seals only through authenticated guest receipt and destroys on rejection', async () => {
  const { createDatabase } = await import('./helpers/database');
  const { createProductionBootstrap } =
    await import('../packages/core/src/composition/signing-runtime');
  const db = await createDatabase();
  let destroyed = false;
  const dataKey = Buffer.alloc(32, 4);
  try {
    await db.query("INSERT INTO users(id,login_name,created_at) VALUES('owner','b@b.c',0)");
    await db.query(
      "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('conn','owner','pending:conn','validating','asc')",
    );
    const transport = {
      request: async (request: { method: string; url: string; body: unknown }) => {
        if (request.method === 'DELETE') {
          destroyed = true;
          return { status: 204, body: bytes({}) };
        }
        const p = JSON.parse(request.body as string);
        const report = request.url.endsWith('/v1/instances')
          ? {
              id: 'bootstrap_vm',
              ownerId: p.ownerId,
              jobId: p.jobId,
              nonce: p.nonce,
              audience: 'a',
              disposable: true,
              expiresAt: Date.now() + 10000,
            }
          : {
              binding: p.binding,
              operation: 'bootstrap-prepare',
              audience: 'a',
              value: { synthetic: 'receipt' },
            };
        return {
          status: 200,
          body: bytes({
            report,
            attestation: createHmac('sha256', key).update(canonicalReport(report)).digest('hex'),
          }),
        };
      },
    };
    const bootstrap = createProductionBootstrap(
      {
        db,
        sealing: {
          issue: async (_lease, _purpose, instanceId) => {
            expect(instanceId).toBe('bootstrap_vm');
            return { grant: { synthetic: true }, dataKey };
          },
          commit: async () => {
            throw Error('synthetic receipt rejected');
          },
        },
        findCertificates: async () => {
          throw Error('must not read Apple');
        },
        createCertificate: async () => {
          throw Error('must not POST Apple');
        },
      },
      {
        endpoint: 'https://runner.example',
        token: 't'.repeat(32),
        audience: 'a',
        proofKey: key,
        transport,
        capabilities: {
          disposableAnalysis: true,
          guestSigning: true,
          sealedMaterials: true,
          appleProvisioning: true,
          bootstrap: true,
        },
      },
    );
    await expect(bootstrap.prove('owner', 'conn', 1)).rejects.toThrow('synthetic receipt rejected');
    expect(destroyed).toBe(true);
    expect(dataKey.equals(Buffer.alloc(32))).toBe(true);
  } finally {
    await db.close();
  }
});
it.each([false, true])(
  'device verifier projects the current wire contract (shared: %s)',
  async (shared) => {
    const { createProductionDeviceVerifier } =
      await import('../packages/core/src/composition/signing-runtime');
    const { createHash } = await import('node:crypto');
    let destroyed = false;
    const cms = Buffer.from('opaque synthetic CMS');
    const digest = createHash('sha256').update(cms).digest('hex');
    const access = {
      ownerId: shared ? 'recipient' : 'o',
      connectionOwnerId: 'o',
      connectionId: 'c',
      generation: 1,
      accessGrantId: shared ? 'share' : null,
      accessGrantGeneration: shared ? 2 : null,
      teamId: 'ABCDEFGHIJ',
    };
    const transport = {
      request: async (request: { method: string; url: string; body: unknown }) => {
        if (request.method === 'DELETE') {
          destroyed = true;
          return { status: 204, body: bytes({}) };
        }
        const p = JSON.parse(request.body as string);
        if (request.url.endsWith('/v1/control/device-profile-verify')) {
          expect(Object.keys(p.binding).sort()).toEqual(
            [
              'ownerId',
              'connectionOwnerId',
              'connectionId',
              'generation',
              'nonce',
              'expiresAt',
              ...(shared ? ['accessGrantId', 'accessGrantGeneration'] : []),
            ].sort(),
          );
        }
        const report = request.url.endsWith('/v1/instances')
          ? {
              id: 'cms_vm',
              ownerId: p.ownerId,
              jobId: p.jobId,
              nonce: p.nonce,
              audience: 'a',
              disposable: true,
              expiresAt: Date.now() + 10000,
            }
          : {
              binding: p.binding,
              operation: 'device-profile-verify',
              audience: 'a',
              value: {
                digest,
                teamId: 'ABCDEFGHIJ',
                bundleId: 'test.control',
                devices: ['a'.repeat(40)],
                certificates: ['b'.repeat(64)],
                expiresAt: Date.now() + 10000,
                profileType: 'ad-hoc',
                entitlements: { 'application-identifier': 'ABCDEFGHIJ.test.*' },
              },
            };
        return {
          status: 200,
          body: bytes({
            report,
            attestation: createHmac('sha256', key).update(canonicalReport(report)).digest('hex'),
          }),
        };
      },
    };
    const verify = createProductionDeviceVerifier({
      endpoint: 'https://runner.example',
      token: 't'.repeat(32),
      audience: 'a',
      proofKey: key,
      transport,
      capabilities: {
        disposableAnalysis: true,
        guestSigning: true,
        sealedMaterials: true,
        appleProvisioning: true,
        bootstrap: true,
      },
    });
    const result = await verify({
      binding: access,
      cms,
      cmsSha256: digest,
      expected: {
        udid: 'a'.repeat(40),
        certificateSha256: 'b'.repeat(64),
        teamId: 'ABCDEFGHIJ',
        bundleId: 'test.control',
      },
      now: Date.now(),
    });
    expect(result.cmsSha256).toBe(digest);
    expect(result.entitlements).toEqual({ 'application-identifier': 'ABCDEFGHIJ.test.*' });
    expect(destroyed).toBe(true);
    destroyed = false;
    await expect(
      verify({
        binding: access,
        cms,
        cmsSha256: digest,
        expected: {
          udid: 'c'.repeat(40),
          certificateSha256: 'b'.repeat(64),
          teamId: 'ABCDEFGHIJ',
          bundleId: 'test.control',
        },
        now: Date.now(),
      }),
    ).rejects.toThrow('CONTROL_PROFILE_PIN_MISMATCH');
    expect(destroyed).toBe(true);
  },
);
it('launch uses the persisted job lease nonce and exposes capacity contention distinctly', async () => {
  const { HttpRunnerProvider } = await import('../packages/core/src/infrastructure/runner-http');
  let launchNonce: unknown;
  const provider = new HttpRunnerProvider({
    endpoint: 'https://runner.synthetic.invalid',
    token: 'a'.repeat(43),
    audience: 'test',
    proofKey: key,
    transport: {
      request: async (request) => {
        launchNonce = JSON.parse(request.body as string).nonce;
        return { status: 409, body: bytes({ error: 'RUNNER_BUSY' }) };
      },
    },
  });
  await expect(provider.launch({ ...input, launchNonce: 'n'.repeat(43) })).rejects.toThrow(
    'RUNNER_BUSY',
  );
  expect(launchNonce).toBe('n'.repeat(43));
});
it('temporary HTTP gateway failures retry even when the proxy returns HTML', async () => {
  const { HttpRunnerProvider } = await import('../packages/core/src/infrastructure/runner-http');
  const provider = new HttpRunnerProvider({
    endpoint: 'https://runner.synthetic.invalid',
    token: 'a'.repeat(43),
    audience: 'test',
    proofKey: key,
    transport: {
      request: async () => ({
        status: 503,
        body: (async function* () {
          yield Buffer.from('<html>temporarily unavailable</html>');
        })(),
      }),
    },
  });
  await expect(provider.launch(input)).rejects.toThrow('RUNNER_TEMPORARY_UNAVAILABLE');
});

it.each([
  ['ARCHIVE_INVALID', 422, 'ARCHIVE_INVALID', 422],
  ['DER_ENTITLEMENTS_UNSUPPORTED', 422, 'DER_ENTITLEMENTS_UNSUPPORTED', 422],
  ['LINUX_SOURCE_CAPACITY_UNSUPPORTED', 422, 'LINUX_SOURCE_CAPACITY_UNSUPPORTED', 422],
  ['ARCHIVE_INVALID', 403, 'RUNNER_REQUEST_REJECTED', 409],
  ['PRIVATE_INTERNAL_ERROR', 422, 'RUNNER_REQUEST_REJECTED', 409],
] as const)(
  'allows only explicit expected broker codes (%s, %i)',
  async (code, status, expected, expectedStatus) => {
    const { HttpRunnerProvider } = await import('../packages/core/src/infrastructure/runner-http');
    const provider = new HttpRunnerProvider({
      endpoint: 'https://runner.synthetic.invalid',
      token: 'a'.repeat(43),
      audience: 'test',
      proofKey: key,
      transport: { request: async () => ({ status, body: bytes({ error: code }) }) },
    });
    await expect(provider.launch(input)).rejects.toMatchObject({
      code: expected,
      status: expectedStatus,
    });
  },
);

it.each(['source', 'analyze'] as const)(
  'preserves semantic %s rejection and consumes the response',
  async (stage) => {
    const { HttpRunnerProvider } = await import('../packages/core/src/infrastructure/runner-http');
    let consumed = false;
    const provider = new HttpRunnerProvider({
      endpoint: 'https://runner.synthetic.invalid',
      token: 'a'.repeat(43),
      audience: 'test',
      proofKey: key,
      transport: {
        request: async (request) => {
          if (request.url.endsWith('/v1/instances')) {
            const payload = JSON.parse(request.body as string);
            const report = {
              id: 'vm',
              ownerId: 'o',
              jobId: 'j',
              nonce: payload.nonce,
              audience: 'test',
              disposable: true,
              expiresAt: Date.now() + 60000,
            };
            return {
              status: 200,
              body: bytes({
                report,
                attestation: createHmac('sha256', key)
                  .update(canonicalReport(report))
                  .digest('hex'),
              }),
            };
          }
          if (request.url.endsWith('/source') && stage === 'analyze')
            return { status: 204, body: (async function* () {})() };
          return {
            status: 422,
            body: (async function* () {
              try {
                yield Buffer.from('{"error":"ARCHIVE_INVALID"}');
              } finally {
                consumed = true;
              }
            })(),
          };
        },
      },
    });
    const vm = await provider.launch(input);
    const grant = {
      ownerId: 'o',
      connectionOwnerId: 'o',
      jobId: 'j',
      leaseToken: 'lease',
      connectionId: 'connection',
      connectionGeneration: 1,
      deviceId: 'device',
      uploadDigest: 'a'.repeat(64),
      taskNonce: 'nonce',
      isolationInstanceId: 'vm',
      expiresAt: Date.now() + 30000,
    };
    await expect(
      vm.analyze({ grant, source: bytes('IPA'), signal: input.signal }),
    ).rejects.toMatchObject({ code: 'ARCHIVE_INVALID', status: 422 });
    expect(consumed).toBe(true);
  },
);
