import { NextRequest, NextResponse } from 'next/server';
import { guardedDownload } from '../../../../../../backend/packages/core/src/library/guarded-download';
import { runtime as getRuntime, origin } from '../../../../../../backend/server/runtime';
import { Failure } from '../../../../../../backend/packages/core/src/shared/index';
import {
  byteRange,
  installManifest,
} from '../../../../../../backend/packages/core/src/library/install';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const headers = {
  'X-Accel-Buffering': 'no',
  'Cache-Control': 'private, no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
};
async function handle(
  request: NextRequest,
  context: {
    params: Promise<{
      cap: string;
      asset: string;
    }>;
  },
) {
  try {
    if (request.headers.get('host') !== new URL(origin).host) throw new Failure('NOT_FOUND', 404);
    const { cap, asset } = await context.params;
    if (!/^[A-Za-z0-9_-]{43}$/.test(cap)) throw new Failure('NOT_FOUND', 404);
    const app = await getRuntime(),
      artifact = await app.tickets.resolve(cap);
    if (asset === 'manifest.plist') {
      const manifest = installManifest(origin, cap, artifact.metadata);
      return new NextResponse(request.method === 'HEAD' ? null : manifest, {
        headers: { ...headers, 'Content-Type': 'application/xml; charset=utf-8' },
      });
    }
    if (asset !== 'application.ipa') throw new Failure('NOT_FOUND', 404);
    const transfer = await app.tickets.beginTransfer(cap);
    const file = await app.artifacts.open(artifact.object_key);
    let transferred = false;
    try {
      const size = (await file.stat()).size;
      const range = byteRange(request.headers.get('range'), size);
      const resultHeaders = {
        ...headers,
        'Content-Type': 'application/octet-stream',
        'Accept-Ranges': 'bytes',
        'Content-Length': String(range.end - range.start + 1),
        ...(range.partial ? { 'Content-Range': `bytes ${range.start}-${range.end}/${size}` } : {}),
      };
      if (request.method === 'HEAD')
        return new NextResponse(null, {
          status: range.partial ? 206 : 200,
          headers: resultHeaders,
        });
      const source = file.createReadStream({ start: range.start, end: range.end, autoClose: true });
      const body = guardedDownload({
        source,
        close: () => file.close(),
        check: () => transfer.check(),
        expiresAt: Math.min(Number(artifact.expires_at), Number(artifact.valid_until)),
        signal: request.signal,
      });
      transferred = true;
      return new NextResponse(body, { status: range.partial ? 206 : 200, headers: resultHeaders });
    } finally {
      if (!transferred) await file.close();
    }
  } catch (error) {
    const failure = error instanceof Failure ? error : new Failure('NOT_FOUND', 404);
    return NextResponse.json({ code: failure.code }, { status: failure.status, headers });
  }
}
export const GET = handle;
export const HEAD = handle;
