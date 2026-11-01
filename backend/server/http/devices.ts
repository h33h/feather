import { presentDevices } from './presenters';
import QRCode from 'qrcode';
import { z } from 'zod';
import { origin } from '../runtime';
import { profileServiceXml } from '../../packages/core/src/devices/onboarding';
import { Failure } from '../../packages/core/src/shared/index';
import { body, response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleDevices(context: AuthenticatedContext) {
  const { request, target, app, raw, csrf, owner } = context;
  if (target === 'devices' && request.method === 'GET')
    return response(
      presentDevices({
        devices: await app.queries.devices(owner),
        collectedDevices: await app.collections.list(owner),
      }),
    );
  if (/^devices\/collected\/[^/]+\/remove$/.test(target) && request.method === 'POST') {
    await app.service.devices.removeIdentity(owner, target.split('/')[2]);
    return response({ ok: true });
  }
  if (target.startsWith('devices/collected/') && request.method === 'GET') {
    const parts = target.split('/');
    if (parts.length === 4 && parts[3] === 'udid')
      return response(await app.collections.reveal(owner, parts[2]));
    throw new Failure('NOT_FOUND', 404);
  }
  if (target === 'devices/challenge' && request.method === 'POST') {
    const challenge = await app.collections.challenge(owner, raw);
    const profileUrl = origin + '/device-profile/' + challenge.challenge;
    return response({
      profileXml: profileServiceXml(origin, challenge.challenge),
      profileUrl,
      qrSvg: await QRCode.toString(profileUrl, {
        type: 'svg',
        errorCorrectionLevel: 'M',
        margin: 4,
        width: 256,
      }),
      expiresAt: challenge.expiresAt,
    });
  }
  if (target.startsWith('devices/') && request.method === 'POST') {
    const parts = target.split('/');
    if (parts[2] === 'register') {
      await app.service.fresh(raw, csrf, request.headers.get('origin') ?? '', origin);
      if (!app.devices) throw new Failure('DEVICE_ONBOARDING_UNAVAILABLE', 503);
      const data = z.object({ slotConsent: z.boolean() }).parse(await body(request));
      return response(await app.devices.register(owner, parts[1], data.slotConsent));
    } else if (parts[2] === 'poll') {
      if (!app.devices) throw new Failure('DEVICE_ONBOARDING_UNAVAILABLE', 503);
      return response(await app.devices.poll(owner, parts[1]));
    } else if (parts[2] === 'os') {
      if (!app.devices) throw new Failure('DEVICE_ONBOARDING_UNAVAILABLE', 503);
      const data = z.object({ version: z.string().max(12) }).parse(await body(request));
      return response(await app.devices.reportOs(owner, parts[1], data.version));
    } else if (parts[2] === 'rename') {
      if (!app.devices) throw new Failure('DEVICE_ONBOARDING_UNAVAILABLE', 503);
      const data = z.object({ name: z.string().max(100) }).parse(await body(request));
      return response(await app.devices.rename(owner, parts[1], data.name));
    } else if (parts[2] === 'select') await app.service.selectDevice(owner, parts[1]);
    else if (parts[2] === 'remove') await app.service.removeDevice(owner, parts[1]);
    else throw new Failure('NOT_FOUND', 404);
    return response({ ok: true });
  }
}
