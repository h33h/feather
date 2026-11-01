import { presentSources, presentReleases } from './presenters';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { Failure } from '../../packages/core/src/shared/index';
import { body, response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleCatalog(context: AuthenticatedContext) {
  const { request, target, app, owner, requireUpload } = context;
  if (target === 'sources' && request.method === 'GET')
    return response(presentSources({ sources: await app.catalogs.list(owner) }));
  if (target === 'catalog/select' && request.method === 'POST') {
    const data = z
      .object({ sourceId: z.string(), releaseId: z.string(), snapshot: z.string() })
      .parse(await body(request));
    await app.importer.select(owner, data.sourceId, data.releaseId, data.snapshot);
    return response({ ok: true });
  }
  if (target === 'catalog/import' && request.method === 'POST') {
    await requireUpload();
    if (!app.capabilities.runner) throw new Failure('NATIVE_PIPELINE_REQUIRED', 503);
    await app.ensureSigningReady?.(owner);
    const data = z
      .object({
        sourceId: z.string(),
        releaseId: z.string(),
        snapshot: z.string(),
        key: z.string().min(1).max(100),
        deviceId: z.string().optional(),
      })
      .parse(await body(request, 16384));
    return response(
      await app.importer.run(owner, data.sourceId, data.releaseId, data.snapshot, request.signal, {
        key: data.key,
        deviceId: data.deviceId,
      }),
      201,
    );
  }
  if (target === 'sources' && request.method === 'POST') {
    const data = z
      .object({
        name: z.string().max(80),
        url: z.string().max(2048),
        trustPublisher: z.literal(true),
      })
      .parse(await body(request));
    const added = await app.catalogs.add(owner, data.name, data.url, [], data.trustPublisher);
    void app.catalogs.refresh(owner, added.id).catch(() => {});
    return response(added, 201);
  }
  if (target.startsWith('sources/')) {
    const parts = target.split('/');
    const sourceId = parts[1];
    if (request.method === 'GET' && parts[2] === 'icons' && parts.length === 4) {
      const icon = await app.catalogs.icon(
        owner,
        sourceId,
        parts[3],
        request.nextUrl.searchParams.get('snapshot') ?? '',
      );
      return new NextResponse(new Uint8Array(icon.bytes), {
        headers: {
          'content-type': icon.type,
          'x-content-type-options': 'nosniff',
          'cache-control': 'private, max-age=300',
          'content-security-policy': "default-src 'none'; sandbox",
        },
      });
    }
    if (request.method === 'GET' && parts[2] === 'releases')
      return response(presentReleases({ releases: await app.catalogs.releases(owner, sourceId) }));
    if (request.method === 'POST') {
      if (parts[2] === 'snapshot') {
        const data = await body(request);
        return response(
          await app.catalogs.snapshot(
            owner,
            sourceId,
            data.feed,
            z.array(z.string()).parse(data.hosts),
          ),
        );
      }
      if (parts[2] === 'refresh')
        return response(await app.catalogs.refresh(owner, sourceId, true));
      if (parts[2] === 'disable') await app.catalogs.disable(owner, sourceId);
      else if (parts[2] === 'remove') await app.catalogs.remove(owner, sourceId);
      else if (parts[2] === 'rename') {
        const data = z.object({ name: z.string().max(80) }).parse(await body(request));
        await app.catalogs.rename(owner, sourceId, data.name);
      } else throw new Failure('NOT_FOUND', 404);
      return response({ ok: true });
    }
  }
}
