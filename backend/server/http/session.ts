import { presentSession } from './presenters';
import { response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleSession({ request, target, app, session }: AuthenticatedContext) {
  if (target !== 'session' || request.method !== 'GET') return null;
  return response(
    presentSession({
      authenticated: true,
      csrf: request.cookies.get('isign-csrf')?.value ?? '',
      profile: {
        id: session.ownerId,
        loginName: session.loginName,
        role: session.role,
        publicProfileId: session.publicProfileId,
      },
      capabilities: app.capabilities,
    }),
  );
}
