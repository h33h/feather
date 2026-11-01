import { presentLibrary, presentHistory } from './presenters';
import { type HistoryStatus } from '../../packages/core/src/library/installation-history';
import { z } from 'zod';
import { Readable } from 'node:stream';
import { origin } from '../runtime';
import { handoffQr } from '../../packages/core/src/library/qr';
import { Failure } from '../../packages/core/src/shared/index';
import { body, response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleLibrary(context: AuthenticatedContext) {
  const { request, target, app, owner, history, requireUpload } = context;
  if (target === 'library' && request.method === 'GET')
    return response(presentLibrary(await app.queries.library(owner)));
  if (target === 'history' && request.method === 'GET')
    return response(
      presentHistory(
        await history.list(owner, {
          cursor: request.nextUrl.searchParams.get('cursor') ?? undefined,
          limit: request.nextUrl.searchParams.has('limit')
            ? Number(request.nextUrl.searchParams.get('limit'))
            : 50,
          status: (request.nextUrl.searchParams.get('status') ?? undefined) as
            HistoryStatus | undefined,
        }),
      ),
    );
  if (target === 'uploads' && request.method === 'POST') {
    await requireUpload();
    if (!app.capabilities.runner) throw new Failure('NATIVE_PIPELINE_REQUIRED', 503);
    await app.ensureSigningReady?.(owner);
    const data = z
      .object({
        name: z
          .string()
          .max(180)
          .regex(/\.ipa$/i),
        key: z.string().min(1).max(100),
        deviceId: z.string().optional(),
      })
      .parse(await body(request, 16384));
    return response(await app.jobs.beginSubmission(owner, { ...data, source: 'upload' }), 201);
  }
  if (/^uploads\/[^/]+$/.test(target) && request.method === 'PUT') {
    await requireUpload();
    if (!request.body) throw new Failure('EMPTY_FILE');
    const uploadId = target.split('/')[1];
    const stream = Readable.fromWeb(request.body as import('node:stream/web').ReadableStream);
    return response(await app.receiveUpload(owner, uploadId, stream, request.signal), 201);
  }
  if (target.startsWith('artifacts/') && request.method === 'POST') {
    const parts = target.split('/');
    if (parts[2] === 'ticket') {
      if (new URL(origin).protocol !== 'https:')
        throw new Failure('HTTPS_INSTALL_ORIGIN_REQUIRED', 503);
      const { ticket, expiresAt } = await app.tickets.issueDetails(owner, parts[1]);
      return response({
        ticket,
        expiresAt,
        installUrl:
          'itms-services://?action=download-manifest&url=' +
          encodeURIComponent(origin + '/install/' + ticket + '/manifest.plist'),
        handoffUrl: origin + '/handoff/' + ticket,
        qrSvg: await handoffQr(origin, ticket),
      });
    }
    throw new Failure('NOT_FOUND', 404);
  }
}
