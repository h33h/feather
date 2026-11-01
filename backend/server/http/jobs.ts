import { z } from 'zod';
import { Failure } from '../../packages/core/src/shared/index';
import { body, response } from './common';
import type { AuthenticatedContext } from './context';
export async function handleJobs(context: AuthenticatedContext) {
  const { request, target, app, owner } = context;
  const requests = app.jobRequests;
  if (target === 'jobs/ensure' && request.method === 'POST') {
    const data = z
      .object({
        uploadId: z.string(),
        deviceId: z.string().optional(),
        key: z.string(),
      })
      .parse(await body(request));
    return response(await requests.ensure(owner, data));
  }
  if (target.startsWith('jobs/') && request.method === 'POST') {
    const parts = target.split('/');
    if (parts[2] === 'cancel') {
      const result = await app.lifecycle.cancel(owner, parts[1]);
      return response(result);
    }
    if (parts[2] === 'retry') {
      return response(await requests.retry(owner, parts[1]));
    }
    throw new Failure('NOT_FOUND', 404);
  }
}
