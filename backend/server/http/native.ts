import { z } from 'zod';
import QRCode from 'qrcode';
import type {
  NativeCommand,
  NativeQuery,
} from '../../packages/core/src/application/native-application';
import { profileServiceXml } from '../../packages/core/src/devices/onboarding';
import type { PublicContext } from './context';
import { body, response } from './common';
import { nativeBearer } from './native-auth';
import { origin } from '../runtime';
const identifier = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9_-]+$/);
const named = z.object({ name: z.string().trim().min(1).max(100) });
/** Native resources never read a cookie or fabricate browser Origin/CSRF credentials. */
export async function handleNative({ request, target, app }: PublicContext) {
  if (!target.startsWith('native/v1/')) return null;
  const raw = nativeBearer(request),
    path = target.slice('native/v1/'.length),
    p = path.split('/');
  const id = (value: string) => identifier.parse(value);
  if (request.method === 'GET') {
    let query: NativeQuery | undefined;
    switch (path) {
      case 'apple':
        query = { kind: 'apple' };
        break;
      case 'devices':
        query = { kind: 'devices' };
        break;
      case 'sources':
        query = { kind: 'sources' };
        break;
      case 'admin/users':
        query = { kind: 'admin.users' };
        break;
      case 'signing/identity':
        query = { kind: 'signing.identity' };
        break;
    }
    if (p.length === 3 && p[0] === 'sources' && p[2] === 'feed')
      query = { kind: 'source.feed', id: id(p[1]) };
    if (p.length === 3 && p[0] === 'signing' && p[1] === 'profiles')
      query = { kind: 'signing.profiles', id: id(p[2]) };
    if (p.length === 4 && p[0] === 'devices' && p[1] === 'collected' && p[3] === 'udid')
      query = { kind: 'device.udid', id: id(p[2]) };
    return query ? response(await app.nativeApplication.view(raw, query)) : null;
  }
  if (request.method === 'DELETE' && p.length === 3 && p[0] === 'admin' && p[1] === 'users')
    return response(
      await app.nativeApplication.command(raw, { kind: 'admin.remove', id: id(p[2]) }),
    );
  if (request.method !== 'POST') return null;
  const data = await body(request, 131072);
  let command: NativeCommand | undefined;
  if (path === 'apple/connect')
    command = {
      kind: 'apple.connect',
      input: z
        .object({
          filename: z.string().max(255),
          issuerId: z.string().max(64),
          keyId: z.string().max(20),
          keyType: z.literal('team').optional(),
          p8: z.string().max(16384),
        })
        .parse(data),
    };
  else if (path === 'apple/disconnect') command = { kind: 'apple.disconnect' };
  else if (path === 'apple/bootstrap') command = { kind: 'apple.bootstrap' };
  else if (path === 'apple/shares')
    command = {
      kind: 'apple.share',
      profileId: z.object({ publicProfileId: z.string().max(64) }).parse(data).publicProfileId,
    };
  else if (p.length === 4 && p[0] === 'apple' && p[1] === 'shares' && p[3] === 'revoke')
    command = { kind: 'apple.revokeShare', id: id(p[2]) };
  else if (path === 'devices/challenge') command = { kind: 'device.challenge' };
  else if (p.length === 4 && p[0] === 'devices' && p[1] === 'collected' && p[3] === 'remove')
    command = { kind: 'device.removeCollected', id: id(p[2]) };
  else if (p.length === 3 && p[0] === 'devices') {
    const device = id(p[1]);
    switch (p[2]) {
      case 'register':
        command = {
          kind: 'device.register',
          id: device,
          ...z.object({ slotConsent: z.boolean() }).parse(data),
        };
        break;
      case 'poll':
        command = { kind: 'device.poll', id: device };
        break;
      case 'select':
        command = { kind: 'device.select', id: device };
        break;
      case 'remove':
        command = { kind: 'device.remove', id: device };
        break;
      case 'rename':
        command = { kind: 'device.rename', id: device, ...named.parse(data) };
        break;
      case 'os':
        command = {
          kind: 'device.os',
          id: device,
          ...z.object({ version: z.string().max(12) }).parse(data),
        };
        break;
    }
  } else if (path === 'sources')
    command = {
      kind: 'source.add',
      ...z
        .object({
          name: z.string().trim().min(1).max(80),
          url: z.string().max(2048),
          trustPublisher: z.literal(true),
        })
        .parse(data),
    };
  else if (p.length === 3 && p[0] === 'sources') {
    const source = id(p[1]);
    switch (p[2]) {
      case 'refresh':
        command = { kind: 'source.refresh', id: source };
        break;
      case 'remove':
        command = { kind: 'source.remove', id: source };
        break;
      case 'disable':
        command = { kind: 'source.disable', id: source };
        break;
      case 'rename':
        command = { kind: 'source.rename', id: source, ...named.parse(data) };
        break;
      case 'download':
        command = {
          kind: 'source.download',
          sourceId: source,
          ...z.object({ releaseId: identifier, snapshot: identifier }).parse(data),
        };
        break;
    }
  } else if (path === 'signing/identity/ensure')
    command = {
      kind: 'signing.ensure',
      ...z.object({ retry: z.boolean().optional() }).parse(data),
    };
  else if (path === 'signing/identity/revoke') command = { kind: 'signing.revoke' };
  else if (path === 'signing/bundle') command = { kind: 'signing.bundle' };
  else if (path === 'signing/profiles/ensure') {
    const parsed = z
      .object({
        deviceIds: z.array(identifier).min(1).max(100),
        bundles: z
          .array(
            z.object({
              bundleId: z.string().min(1).max(255),
              entitlements: z.record(z.string(), z.unknown()),
            }),
          )
          .min(1)
          .max(50),
        retry: z.boolean().optional(),
      })
      .parse(data);
    command = {
      kind: 'signing.profiles',
      request: { deviceIds: parsed.deviceIds, bundles: parsed.bundles },
      ...(parsed.retry === undefined ? {} : { retry: parsed.retry }),
    };
  } else if (path === 'admin/invites')
    command = {
      kind: 'admin.invite',
      ...z.object({ name: z.string().trim().min(1).max(40) }).parse(data),
    };
  else if (p.length === 4 && p[0] === 'admin' && p[1] === 'users') {
    const user = id(p[2]);
    if (p[3] === 'reinvite') command = { kind: 'admin.reinvite', id: user };
    if (p[3] === 'block') command = { kind: 'admin.block', id: user };
    if (p[3] === 'unblock') command = { kind: 'admin.unblock', id: user };
  } else if (path === 'account/delete') command = { kind: 'account.delete' };
  if (!command) return null;
  const result = await app.nativeApplication.command(raw, command);
  if (command.kind === 'device.challenge') {
    const issued = z
      .object({ challenge: z.string().regex(/^[A-Za-z0-9_-]{43}$/), expiresAt: z.number() })
      .parse(result);
    const profileUrl = origin + '/device-profile/' + issued.challenge;
    return response({
      profileUrl,
      profileXml: profileServiceXml(origin, issued.challenge),
      expiresAt: issued.expiresAt,
      qrSvg: await QRCode.toString(profileUrl, { type: 'svg', margin: 4, width: 256 }),
    });
  }
  return response(result);
}
