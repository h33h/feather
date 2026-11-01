import { it, expect, vi } from 'vitest';
import { normalizeGBox } from '../packages/core/src/catalog/gbox';
import {
  validateUrl,
  isPublicAddress,
  fetchSafe,
  fetchSafeStream,
} from '../packages/core/src/catalog/safe-fetch';
const feed = {
  appRepositories: [
    {
      appName: 'Приложение',
      appVersion: '1.0',
      appPackage: 'https://downloads.example.invalid/one.ipa',
    },
  ],
};
it('normalizes declared releases without inventing build or digest', () => {
  const result = normalizeGBox(feed);
  expect(result).toHaveLength(1);
  expect(result[0].version).toBe('1.0');
  expect(result[0].build).toBeNull();
  expect(result[0].digest).toBeNull();
});
it('rejects placeholder, schema drift, duplicate identity and unsafe metadata', () => {
  for (const value of [
    { items: [] },
    { appRepositories: [{}] },
    { appRepositories: [{ ...feed.appRepositories[0], appPackage: 'placeholder' }] },
  ])
    expect(() => normalizeGBox(value)).toThrow();
  expect(() =>
    normalizeGBox({ appRepositories: [feed.appRepositories[0], feed.appRepositories[0]] }),
  ).toThrow('DUPLICATE_RELEASE');
});
it('forbids private, metadata, mapped, reserved IPv4 and IPv6 addresses', () => {
  for (const ip of [
    '127.0.0.1',
    '10.1.2.3',
    '169.254.169.254',
    '100.64.0.1',
    '192.168.1.1',
    '0.0.0.0',
    '198.18.1.1',
    '224.0.0.1',
    '::1',
    '::',
    'fc00::1',
    'fe80::1',
    '::ffff:127.0.0.1',
    '2001:db8::1',
  ])
    expect(isPublicAddress(ip), ip).toBe(false);
  expect(isPublicAddress('1.1.1.1')).toBe(true);
});
it('rejects non HTTPS, credentials, fragments and ports', () => {
  for (const url of [
    'http://example.com/x',
    'https://user:pass@example.com/x',
    'https://example.com:8443/x',
    'https://example.com/x#bad',
    'https://localhost/x',
  ])
    expect(() => validateUrl(url)).toThrow();
});
it('fails before transport if any resolved address is private', async () => {
  let called = false;
  await expect(
    fetchSafe('https://feed.example.invalid/feed', {
      hosts: ['feed.example.invalid'],
      resolve: async () => [
        { address: '1.1.1.1', family: 4 },
        { address: '127.0.0.1', family: 4 },
      ],
      transport: async () => {
        called = true;
        throw new Error('unexpected');
      },
    }),
  ).rejects.toThrow('SSRF_BLOCKED');
  expect(called).toBe(false);
});
it('pins DNS resolution and strips credentials across origin redirects', async () => {
  const seen: { address: string; headers: Record<string, string> }[] = [];
  let step = 0;
  await fetchSafe('https://one.example.invalid/feed', {
    hosts: ['one.example.invalid', 'two.example.invalid'],
    credentials: { origin: 'https://one.example.invalid', authorization: 'synthetic-secret' },
    resolve: async () => [{ address: '1.1.1.1', family: 4 }],
    transport: async (_url, address, headers) => {
      seen.push({ address: address.address, headers });
      return step++ === 0
        ? {
            status: 302,
            headers: { location: 'https://two.example.invalid/ipa' },
            body: (async function* () {})(),
          }
        : {
            status: 200,
            headers: {} as Record<string, string>,
            body: (async function* () {
              yield Buffer.from('ok');
            })(),
          };
    },
  });
  expect(seen.map((x) => x.address)).toEqual(['1.1.1.1', '1.1.1.1']);
  expect(seen[0].headers.authorization).toBe('synthetic-secret');
  expect(seen[1].headers.authorization).toBeUndefined();
});
it('redirect to unapproved host or private address never reaches it', async () => {
  let calls = 0;
  await expect(
    fetchSafe('https://one.example.invalid/feed', {
      hosts: ['one.example.invalid'],
      resolve: async () => [{ address: '1.1.1.1', family: 4 }],
      transport: async () => {
        calls++;
        return {
          status: 302,
          headers: { location: 'https://169.254.169.254/latest' },
          body: (async function* () {})(),
        };
      },
    }),
  ).rejects.toThrow();
  expect(calls).toBe(1);
});
it('enforces actual response size without content length', async () => {
  await expect(
    fetchSafe('https://one.example.invalid/feed', {
      hosts: ['one.example.invalid'],
      maxBytes: 2,
      resolve: async () => [{ address: '1.1.1.1', family: 4 }],
      transport: async () => ({
        status: 200,
        headers: {} as Record<string, string>,
        body: (async function* () {
          yield Buffer.from('three');
        })(),
      }),
    }),
  ).rejects.toThrow('REMOTE_TOO_LARGE');
});
it('aborts connection on early oversized content-length before consuming body', async () => {
  let signal: AbortSignal | undefined;
  await expect(
    fetchSafe('https://one.example.invalid/feed', {
      hosts: ['one.example.invalid'],
      maxBytes: 2,
      resolve: async () => [{ address: '1.1.1.1', family: 4 }],
      transport: async (_u, _a, _h, s) => {
        signal = s;
        return {
          status: 200,
          headers: { 'content-length': '100' },
          body: (async function* () {
            yield Buffer.from('no');
          })(),
        };
      },
    }),
  ).rejects.toThrow('REMOTE_TOO_LARGE');
  expect(signal?.aborted).toBe(true);
});

it('preserves bounded query signatures while retaining SSRF and redirect guards', async () => {
  const value =
    'https://files.example.invalid/app.ipa?X-Amz-Signature=synthetic%2Bsignature&raw=true';
  expect(validateUrl(value).href).toBe(value);
  let received = '';
  await fetchSafe(value, {
    hosts: ['files.example.invalid'],
    maxBytes: 2,
    resolve: async () => [{ address: '1.1.1.1', family: 4 }],
    transport: async (url) => {
      received = url.href;
      return {
        status: 200,
        headers: {},
        body: (async function* () {
          yield Buffer.from('ok');
        })(),
      };
    },
  });
  expect(received).toBe(value);
  await expect(
    fetchSafe(value, {
      hosts: ['files.example.invalid'],
      resolve: async () => [{ address: '1.1.1.1', family: 4 }],
      transport: async () => {
        throw new Error(value);
      },
    }),
  ).rejects.toThrow('REMOTE_UNAVAILABLE');
  expect(() => validateUrl(value + 'x'.repeat(2048))).toThrow('UNSAFE_SOURCE_URL');
});
it('normalizes the authorized decoded iApps GBox export and keeps missing packages unavailable', async () => {
  const { readFile } = await import('node:fs/promises');
  const raw = JSON.parse(
    await readFile(
      new URL('./fixtures/iapps-full-repository-decoded.json', import.meta.url),
      'utf8',
    ),
  );
  const releases = normalizeGBox(raw);
  expect(releases.length).toBe(1654);
  expect(releases.filter((r) => !r.url)).toHaveLength(2);
  expect(releases.some((r) => r.url && new URL(r.url).hostname === 'storage.iapps.rejail.ru')).toBe(
    true,
  );
  expect(
    releases.some(
      (r) =>
        r.url &&
        new URL(r.url).hostname === 'github.com' &&
        new URL(r.url).searchParams.get('raw') === 'true',
    ),
  ).toBe(true);
  expect(releases.every((r) => !r.url || new URL(r.url).protocol === 'https:')).toBe(true);
});
it('keeps metadata-only catalog entries visible without inventing a download', () => {
  const releases = normalizeGBox({
    appRepositories: [
      { appName: 'Информация', appVersion: '', appImage: 'https://icons.example.invalid/icon.png' },
    ],
  });
  expect(releases).toHaveLength(1);
  expect(releases[0].url).toBe('');
  expect(releases[0].iconUrl).toContain('/icon.png');
});

it('bounds descriptor preflight even if DNS lookup or headers never arrive', async () => {
  vi.useFakeTimers();
  try {
    for (const phase of ['dns', 'headers']) {
      const pending = fetchSafeStream('https://files.example.invalid/app.ipa', {
        hosts: ['files.example.invalid'],
        timeoutMs: 10,
        resolve: () =>
          phase === 'dns'
            ? new Promise(() => {})
            : Promise.resolve([{ address: '1.1.1.1', family: 4 }]),
        transport: () => new Promise(() => {}),
      });
      const rejected = expect(pending).rejects.toThrow('REMOTE_TIMEOUT');
      await vi.advanceTimersByTimeAsync(11);
      await rejected;
    }
  } finally {
    vi.useRealTimers();
  }
});
