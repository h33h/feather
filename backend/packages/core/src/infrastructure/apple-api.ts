import type { AppleRequestPort } from '../apple/request-port';
import { sign, type KeyObject } from 'node:crypto';
import { Failure } from '../shared/index';
const origin = 'https://api.appstoreconnect.apple.com';
const allowed = new Set(['/v1/devices', '/v1/bundleIds', '/v1/certificates', '/v1/profiles']);
function allowedPath(path: string) {
  return (
    allowed.has(path) ||
    /^\/v1\/(?:devices|bundleIds|certificates|profiles)\/[A-Za-z0-9_-]{1,128}$/.test(path) ||
    /^\/v1\/profiles\/[A-Za-z0-9_-]{1,128}\/(?:relationships\/)?(?:devices|bundleId|certificates)$/.test(
      path,
    )
  );
}
export function appleJwt(
  config: {
    issuerId: string;
    keyId: string;
    privateKey: KeyObject;
  },
  method: 'GET' | 'POST' | 'DELETE',
  resource: string,
  nowSeconds: number,
) {
  const url = new URL(resource, origin);
  url.search = url.searchParams.toString();
  if (url.origin !== origin || !allowedPath(url.pathname) || url.hash)
    throw new Failure('APPLE_RESOURCE_NOT_ALLOWED');
  const claims: Record<string, unknown> = {
    iss: config.issuerId,
    iat: Math.floor(nowSeconds),
    exp: Math.floor(nowSeconds) + 120,
    aud: 'appstoreconnect-v1',
  };
  if (method === 'GET') claims.scope = ['GET ' + url.pathname + url.search];
  const header = Buffer.from(
    JSON.stringify({ alg: 'ES256', kid: config.keyId, typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = sign('sha256', Buffer.from(header + '.' + payload), {
    key: config.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  return header + '.' + payload + '.' + signature;
}
export type AppleResponse = {
  status: number;
  data: unknown;
  requestId?: string;
};
export class AppleClient implements AppleRequestPort {
  constructor(
    private jwt: (method: 'GET' | 'POST' | 'DELETE', path: string) => Promise<string>,
    private transport: (
      method: string,
      url: string,
      jwt: string,
      body?: unknown,
    ) => Promise<AppleResponse>,
    private delay: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  ) {}
  async request(method: 'GET' | 'POST' | 'DELETE', resource: string, body?: unknown) {
    const url = new URL(resource, origin);
    url.search = url.searchParams.toString();
    if (
      url.origin !== origin ||
      !allowedPath(url.pathname) ||
      url.username ||
      url.password ||
      url.hash
    )
      throw new Failure('APPLE_RESOURCE_NOT_ALLOWED');
    const attempts = method === 'GET' ? 3 : 1;
    for (let n = 0; n < attempts; n++) {
      let response: AppleResponse;
      try {
        response = await this.transport(
          method,
          url.href,
          await this.jwt(method, url.pathname + url.search),
          body,
        );
      } catch {
        if (method !== 'GET') throw new Failure('MUTATION_OUTCOME_UNKNOWN', 409);
        if (n + 1 === attempts) throw new Failure('APPLE_TEMPORARY_UNAVAILABLE', 503);
        await this.delay(100 * 2 ** n);
        continue;
      }
      if (response.status >= 200 && response.status < 300) return response.data;
      // An explicit owner revoke can be repeated after a lost successful response.
      if (
        method === 'DELETE' &&
        /^\/v1\/certificates\/[A-Za-z0-9_-]{1,128}$/.test(url.pathname) &&
        response.status === 404
      )
        return null;
      if (response.status === 401 || response.status === 403)
        throw new Failure('APPLE_ACCESS_ACTION_REQUIRED', 403);
      if (response.status === 429 || response.status >= 500) {
        if (method !== 'GET')
          throw new Failure(
            response.status >= 500 ? 'MUTATION_OUTCOME_UNKNOWN' : 'APPLE_RATE_LIMITED',
            409,
          );
        if (n + 1 < attempts) {
          await this.delay(100 * 2 ** n);
          continue;
        }
        throw new Failure('APPLE_TEMPORARY_UNAVAILABLE', 503);
      }
      // ErrorResponse source pointers follow Apple's documented error format.
      // Only an explicit identifier-unavailability response may trigger automatic mapping.
      const errors = (
        response.data as {
          errors?: { code?: string; source?: { pointer?: string }; detail?: string }[];
        } | null
      )?.errors;
      if (
        method === 'POST' &&
        url.pathname === '/v1/bundleIds' &&
        response.status === 409 &&
        Array.isArray(errors) &&
        errors.some(
          (error) =>
            error.source?.pointer === '/data/attributes/identifier' &&
            error.code?.startsWith('ENTITY_ERROR.') &&
            typeof error.detail === 'string' &&
            /not available|already (?:exists|registered|taken)/i.test(error.detail),
        )
      )
        throw new Failure('BUNDLE_IDENTIFIER_UNAVAILABLE', 409);
      throw new Failure('APPLE_OPERATION_REJECTED', 409);
    }
    throw new Failure('APPLE_TEMPORARY_UNAVAILABLE', 503);
  }
}
