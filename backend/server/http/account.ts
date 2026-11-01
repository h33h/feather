import { response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleAccount(context: AuthenticatedContext) {
  const { request, target, app, raw } = context;
  if (target === 'auth/logout' && request.method === 'POST') {
    await app.sessions.logout(raw);
    const result = response({ ok: true });
    result.cookies.delete('__Host-isign-session');
    result.cookies.delete('isign-csrf');
    return result;
  }
}
