import { z } from 'zod';
import { origin } from '../runtime';
import { Failure } from '../../packages/core/src/shared/errors';
import { body, response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleAdmin(context: AuthenticatedContext) {
  const { target, request, app, owner, raw, csrf, session } = context;
  if (!target.startsWith('admin/')) return null;
  await app.authorization.requireAdmin(session);
  if (!app.admin) throw new Failure('ADMIN_UNAVAILABLE', 503);
  if (target === 'admin/users' && request.method === 'GET')
    return response({ users: await app.admin.list(owner) });
  await app.service.fresh(raw, csrf, request.headers.get('origin') ?? '', origin);
  if (target === 'admin/invites' && request.method === 'POST') {
    const data = z.object({ name: z.string().min(1).max(40) }).parse(await body(request, 16384));
    return response(await app.admin.invite(owner, data.name), 201);
  }
  const match = /^admin\/users\/([^/]{1,100})(?:\/(reinvite|block|unblock))?$/.exec(target);
  if (!match) throw new Failure('NOT_FOUND', 404);
  const [, userId, action] = match;
  if (request.method === 'POST' && action === 'reinvite')
    return response(await app.admin.reinvite(owner, userId));
  if (request.method === 'POST' && (action === 'block' || action === 'unblock')) {
    await app.admin.setBlocked(owner, userId, action === 'block');
    return response({ ok: true });
  }
  if (request.method === 'DELETE' && !action) {
    await app.admin.remove(owner, userId);
    return response({ ok: true });
  }
  throw new Failure('NOT_FOUND', 404);
}
