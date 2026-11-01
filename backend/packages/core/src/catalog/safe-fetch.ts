import https from 'node:https';
import { lookup } from 'node:dns/promises';
import ipaddr from 'ipaddr.js';
import type { LookupAddress } from 'node:dns';
import { Failure } from '../shared/index';
export function isPublicAddress(value: string) {
  try {
    const parsed = ipaddr.parse(value);
    return (
      parsed.range() === 'unicast' &&
      !(parsed.kind() === 'ipv6' && (parsed as ipaddr.IPv6).isIPv4MappedAddress())
    );
  } catch {
    return false;
  }
}
export function validateUrl(value: string) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Failure('INVALID_SOURCE_URL');
  }
  if (
    value.length > 2048 ||
    /[\x00-\x20\x7f]/.test(value) ||
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.hash ||
    (url.port && url.port !== '443') ||
    url.hostname === 'localhost' ||
    url.hostname.endsWith('.localhost') ||
    url.hostname.endsWith('.local') ||
    url.hostname.endsWith('.') ||
    url.hostname.includes('%')
  )
    throw new Failure('UNSAFE_SOURCE_URL');
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (ipaddr.isValid(host) && !isPublicAddress(host)) throw new Failure('SSRF_BLOCKED');
  return url;
}
export type Response = {
  status: number;
  headers: Record<string, string>;
  body: AsyncIterable<Uint8Array>;
};
export type Options = {
  hosts: string[];
  maxBytes?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  credentials?: {
    origin: string;
    authorization: string;
  };
  resolve?: (host: string) => Promise<LookupAddress[]>;
  transport?: (
    url: URL,
    address: LookupAddress,
    headers: Record<string, string>,
    signal: AbortSignal,
  ) => Promise<Response>;
};
async function transport(
  url: URL,
  address: LookupAddress,
  headers: Record<string, string>,
  signal: AbortSignal,
): Promise<Response> {
  return new Promise((resolve, reject) => {
    const request = https.request(
      url,
      {
        method: 'GET',
        agent: false,
        headers,
        signal,
        lookup: (_host, opts, callback) => {
          if (opts.all) callback(null, [address]);
          else callback(null, address.address, address.family);
        },
      },
      (res) => {
        const safeHeaders: Record<string, string> = {};
        for (const [key, value] of Object.entries(res.headers))
          if (typeof value === 'string') safeHeaders[key] = value;
        resolve({ status: res.statusCode ?? 0, headers: safeHeaders, body: res });
      },
    );
    request.on('error', () => reject(new Failure('REMOTE_UNAVAILABLE', 502)));
    request.end();
  });
}
export async function fetchSafeStream(value: string, options: Options) {
  let url = validateUrl(value);
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), options.timeoutMs ?? 30000);
  deadline.unref();
  const cancel = () => controller.abort();
  options.signal?.addEventListener('abort', cancel, { once: true });
  if (options.signal?.aborted) controller.abort();
  const stop = () => {
    clearTimeout(deadline);
    options.signal?.removeEventListener('abort', cancel);
  };
  const untilAbort = <T>(operation: Promise<T>) =>
    new Promise<T>((resolve, reject) => {
      const cleanup = () => controller.signal.removeEventListener('abort', aborted);
      const aborted = () => {
        cleanup();
        reject(new Failure('REMOTE_TIMEOUT', 504));
      };
      controller.signal.addEventListener('abort', aborted, { once: true });
      operation.then(
        (value) => {
          cleanup();
          resolve(value);
        },
        (error) => {
          cleanup();
          reject(error);
        },
      );
      if (controller.signal.aborted) aborted();
    });
  try {
    for (let hop = 0; hop <= 5; hop++) {
      if (controller.signal.aborted) throw new Failure('REMOTE_TIMEOUT', 504);
      if (!options.hosts.includes(url.hostname)) throw new Failure('ARTIFACT_HOST_NOT_APPROVED');
      const addresses = await untilAbort(
        (options.resolve ?? ((h) => lookup(h, { all: true, verbatim: true })))(url.hostname),
      );
      if (!addresses.length || addresses.some((a) => !isPublicAddress(a.address)))
        throw new Failure('SSRF_BLOCKED');
      const headers: Record<string, string> = {
        accept: 'application/json, application/octet-stream',
        'accept-encoding': 'identity',
      };
      if (options.credentials && url.origin === options.credentials.origin)
        headers.authorization = options.credentials.authorization;
      const response = await untilAbort(
        (options.transport ?? transport)(url, addresses[0], headers, controller.signal),
      );
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        // Closing an iterator destroys a Node response without following redirects.
        const iterator = response.body[Symbol.asyncIterator]();
        await iterator.return?.();
        if (hop === 5 || !response.headers.location) throw new Failure('REMOTE_REDIRECT_LIMIT');
        url = validateUrl(new URL(response.headers.location, url).href);
        continue;
      }
      if (response.status !== 200) {
        const iterator = response.body[Symbol.asyncIterator]();
        await iterator.return?.();
        throw new Failure(
          response.status === 401 || response.status === 403
            ? 'SOURCE_ACCESS_REQUIRED'
            : response.status === 429
              ? 'SOURCE_RATE_LIMITED'
              : response.status === 404
                ? 'RELEASE_UNAVAILABLE'
                : 'REMOTE_UNAVAILABLE',
          502,
        );
      }
      if (
        response.headers['content-encoding'] &&
        response.headers['content-encoding'] !== 'identity'
      )
        throw new Failure('REMOTE_ENCODING_UNSUPPORTED');
      const max = options.maxBytes ?? 8 * 1024 ** 2;
      if (response.headers['content-length'] && Number(response.headers['content-length']) > max)
        throw new Failure('REMOTE_TOO_LARGE', 413);
      const body = (async function* () {
        let size = 0;
        try {
          for await (const chunk of response.body) {
            if (controller.signal.aborted) throw new Failure('REMOTE_TIMEOUT', 504);
            size += chunk.byteLength;
            if (size > max) throw new Failure('REMOTE_TOO_LARGE', 413);
            yield chunk;
          }
        } finally {
          controller.abort();
          stop();
          const iterator = response.body[Symbol.asyncIterator]();
          await iterator.return?.();
        }
      })();
      return {
        body,
        finalOrigin: url.origin,
        finalUrl: url.href,
        // A descriptor resolver needs only the redirect target. Aborting closes
        // the HTTPS request even when the lazy body iterator was never started.
        close: async () => {
          controller.abort();
          stop();
          const iterator = response.body[Symbol.asyncIterator]();
          await iterator.return?.();
        },
      };
    }
    throw new Failure('REMOTE_REDIRECT_LIMIT');
  } catch (error) {
    controller.abort();
    stop();
    if (error instanceof Failure) throw error;
    throw new Failure('REMOTE_UNAVAILABLE', 502);
  }
}
export async function fetchSafe(value: string, options: Options) {
  const result = await fetchSafeStream(value, options);
  const parts = [];
  for await (const chunk of result.body) parts.push(Buffer.from(chunk));
  return Buffer.concat(parts);
}
