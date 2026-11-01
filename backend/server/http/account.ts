import { origin } from '../runtime';
import { response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleAccount(context: AuthenticatedContext) {
  const { request, target, app, raw, csrf } = context;
  if (target === 'auth/logout' && request.method === 'POST') {
    await app.service.logout(raw);
    const result = response({ ok: true });
    result.cookies.delete('__Host-isign-session');
    result.cookies.delete('isign-csrf');
    return result;
  }
  if (target === 'account/delete' && request.method === 'POST') {
    await app.lifecycle.deleteAccount(raw, csrf, request.headers.get('origin') ?? '', origin);
    const result = response({ ok: true });
    result.cookies.delete('__Host-isign-session');
    result.cookies.delete('isign-csrf');
    return result;
  }
}
