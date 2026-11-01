import { isIP } from 'node:net';
import { inspect } from 'node:util';
import path from 'node:path';
import { ProviderError } from '../shared/errors';
/** Explicit disclosure is reserved for server-side provider construction. */
export class ServerSecret {
  #value: string;
  constructor(value: string) {
    this.#value = value;
  }
  reveal() {
    return this.#value;
  }
  toJSON() {
    return '[REDACTED]';
  }
  toString() {
    return '[REDACTED]';
  }
  [inspect.custom]() {
    return '[REDACTED]';
  }
}
export function requireServer() {
  if (typeof window !== 'undefined') throw new ProviderError('SERVER_ONLY');
}
export function httpsEndpoint(value: string, originOnly = false) {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ProviderError('INVALID_HTTPS_ENDPOINT');
  }
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ||
    (originOnly && url.pathname !== '/')
  )
    throw new ProviderError('INVALID_HTTPS_ENDPOINT');
  return url;
}
export type HttpTransport = (url: string, init: RequestInit) => Promise<Response>;
/** No ambient network: callers must explicitly inject fetch or a fixture. No redirects/retries. */
export async function providerRequest<T>(
  transport: HttpTransport | undefined,
  url: URL,
  init: RequestInit,
  consume: (response: Response) => Promise<T>,
  timeoutMs = 10000,
): Promise<T> {
  requireServer();
  if (!transport) throw new ProviderError('PROVIDER_TRANSPORT_DISABLED');
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000)
    throw new ProviderError('INVALID_TIMEOUT');
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve()
        .then(() => transport(url.href, { ...init, redirect: 'error', signal: controller.signal }))
        .then(consume),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new ProviderError('PROVIDER_TIMEOUT'));
        }, timeoutMs);
      }),
    ]);
  } catch (error) {
    if (error instanceof ProviderError) throw error;
    throw new ProviderError('PROVIDER_UNAVAILABLE');
  } finally {
    if (timer) clearTimeout(timer);
  }
}
export type PersonalConfig = {
  mode: 'personal';
  origin: string;
  databaseUrl: ServerSecret;
  databaseTransport: 'private-bridge' | 'tls' | 'loopback';
  dataDirectory: string;
  keyFile: string;
  runner: { origin: string; token: ServerSecret; audience: string };
};
export function loadProviderConfig(env: Record<string, string | undefined>): PersonalConfig {
  requireServer();
  if (env.ISIGN_RUNTIME && env.ISIGN_RUNTIME !== 'personal')
    throw new ProviderError('PERSONAL_RUNTIME_REQUIRED');
  const required = (name: string) => {
    const value = env[name];
    if (!value?.trim()) throw new ProviderError('CONFIG_REQUIRED:' + name);
    return value;
  };
  for (const [name, value] of Object.entries(env))
    if (
      name.startsWith('NEXT_PUBLIC_') &&
      /(TOKEN|SECRET|KEY|DATABASE|PASSWORD|CREDENTIAL)/i.test(name) &&
      value
    )
      throw new ProviderError('PUBLIC_SECRET_FORBIDDEN');
  const originUrl = new URL(required('ISIGN_ORIGIN'));
  if (isIP(originUrl.hostname.replace(/^\[|\]$/g, '')))
    throw new ProviderError('PASSKEY_ORIGIN_DOMAIN_REQUIRED');
  const loopback = originUrl.hostname === 'localhost';
  if (
    originUrl.username ||
    originUrl.password ||
    originUrl.search ||
    originUrl.hash ||
    originUrl.pathname !== '/' ||
    !(
      originUrl.protocol === 'https:' ||
      (originUrl.protocol === 'http:' && loopback && env.NODE_ENV !== 'production')
    )
  )
    throw new ProviderError('HTTPS_OR_LOOPBACK_ORIGIN_REQUIRED');
  const db = new URL(required('DATABASE_URL'));
  if (
    !['postgres:', 'postgresql:'].includes(db.protocol) ||
    !db.hostname ||
    !db.pathname.slice(1) ||
    !db.username ||
    !db.password ||
    db.hash
  )
    throw new ProviderError('DATABASE_CONFIG_INVALID');
  const transport = required('ISIGN_PERSONAL_DATABASE_TRANSPORT');
  if (transport === 'private-bridge') {
    if (db.hostname !== 'postgres' || db.search)
      throw new ProviderError('PERSONAL_DATABASE_BRIDGE_REQUIRED');
  } else if (transport === 'loopback') {
    if (
      !['127.0.0.1', 'localhost', '[::1]'].includes(db.hostname) ||
      env.NODE_ENV === 'production' ||
      db.search
    )
      throw new ProviderError('LOOPBACK_DATABASE_REQUIRED');
  } else if (
    transport !== 'tls' ||
    !['verify-full', 'verify-ca'].includes(db.searchParams.get('sslmode') ?? '')
  )
    throw new ProviderError('DATABASE_TLS_REQUIRED');
  const absolute = (name: string) => {
    const value = required(name);
    if (!path.isAbsolute(value) || path.normalize(value) !== value || value === '/')
      throw new ProviderError('PERSONAL_PATH_INVALID');
    return value;
  };
  const dataDirectory = absolute('ISIGN_PERSONAL_DATA'),
    keyFile = absolute('ISIGN_PERSONAL_KEY_FILE');
  if (keyFile.startsWith(dataDirectory + '/'))
    throw new ProviderError('PERSONAL_KEY_SEPARATION_REQUIRED');
  const token = required('ISIGN_RUNNER_TOKEN'),
    audience = required('ISIGN_RUNNER_AUDIENCE');
  if (token.length < 32 || /[\r\n]/.test(token) || !/^[a-zA-Z0-9:_-]{1,100}$/.test(audience))
    throw new ProviderError('RUNNER_AUTH_INVALID');
  return {
    mode: 'personal',
    origin: originUrl.origin,
    databaseUrl: new ServerSecret(db.href),
    databaseTransport: transport as PersonalConfig['databaseTransport'],
    dataDirectory,
    keyFile,
    runner: {
      origin: httpsEndpoint(required('ISIGN_RUNNER_ORIGIN'), true).origin,
      token: new ServerSecret(token),
      audience,
    },
  };
}
/** Consume trusted-provider metadata without permitting an unbounded response allocation. */
export async function boundedResponseText(response: Response, maxBytes: number) {
  const declared = response.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > maxBytes))
    throw new ProviderError('PROVIDER_RESPONSE_INVALID');
  const reader = response.body?.getReader();
  if (!reader) return '';
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maxBytes) throw new ProviderError('PROVIDER_RESPONSE_INVALID');
      chunks.push(Buffer.from(part.value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, size).toString('utf8');
}
