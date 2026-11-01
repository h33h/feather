import { z } from 'zod';
import { origin } from '../runtime';
import { handoffQr } from '../../packages/core/src/library/qr';
import { Failure } from '../../packages/core/src/shared';
import { body, response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleClientInstaller({
  request,
  target,
  app,
  owner,
  raw,
  csrf,
}: AuthenticatedContext) {
  if (target === 'client/install' && request.method === 'POST') {
    const input = z
      .object({
        deviceId: z.string().min(1).max(100),
        key: z.string().regex(/^[A-Za-z0-9_-]{1,100}$/),
      })
      .strict()
      .parse(await body(request, 4096));
    await app.sessions.fresh(raw, csrf, request.headers.get('origin') ?? '', origin);
    return response(await app.clientInstaller.begin(owner, input));
  }
  if (/^client\/install\/[^/]+$/.test(target) && request.method === 'GET')
    return response(await app.clientInstaller.view(owner, target.split('/')[2]));
  if (/^client\/install\/[^/]+\/ticket$/.test(target) && request.method === 'POST') {
    z.object({})
      .strict()
      .parse(await body(request, 4096));
    await app.sessions.fresh(raw, csrf, request.headers.get('origin') ?? '', origin);
    if (new URL(origin).protocol !== 'https:')
      throw new Failure('HTTPS_INSTALL_ORIGIN_REQUIRED', 503);
    const { ticket, expiresAt } = await app.clientInstaller.ticket(owner, target.split('/')[2]);
    return response({
      expiresAt,
      installUrl:
        'itms-services://?action=download-manifest&url=' +
        encodeURIComponent(origin + '/install/' + ticket + '/manifest.plist'),
      handoffUrl: origin + '/handoff/' + ticket,
      qrSvg: await handoffQr(origin, ticket),
    });
  }
}
