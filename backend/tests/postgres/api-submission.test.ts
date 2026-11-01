import { ReceiveUpload } from '../../packages/core/src/application/receive-upload';
import { JobRequests } from '../../packages/core/src/application/job-requests';
import { RequestAuthorization } from '../../packages/core/src/application/request-authorization';
import { RequestLifecycle } from '../../packages/core/src/application/request-lifecycle';
import { InstallationHistory } from '../../packages/core/src/library/installation-history';
import { expect, it, vi } from 'vitest';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { Readable } from 'node:stream';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { postgresFixture } from '../helpers/postgres';
import { initializeDatabase } from '../../packages/core/src/infrastructure/database-init';
import { loginFixture, connectionFixture, deviceFixture } from '../helpers/login';
import { Service } from '../../packages/core/src/application/service';
import { JobsActions } from '../../packages/core/src/signing/jobs-actions';
import {
  PersonalObjects,
  PersonalStorage,
  PersonalArtifacts,
} from '../../packages/core/src/library/personal-storage';
import { RuntimeQueries } from '../../packages/core/src/application/queries';
const state = vi.hoisted(() => ({ origin: '', app: null as unknown }));
vi.mock('../../server/runtime', () => ({
  get origin() {
    return state.origin;
  },
  runtime: async () => state.app,
}));
import { handle } from '../../server/http/router';
it('receives and cancels an IPA through real HTTP routing, sessions, PostgreSQL and filesystem', async () => {
  const fixture = await postgresFixture(),
    directory = await mkdtemp(join(tmpdir(), 'isign-http-'));
  const server = createServer(async (request, response) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.from(chunk));
      const headers = new Headers();
      for (const [key, value] of Object.entries(request.headers))
        if (value) headers.set(key, Array.isArray(value) ? value.join(',') : value);
      const result = await handle(
        new NextRequest(new URL(request.url!, state.origin), {
          method: request.method,
          headers,
          ...(request.method === 'GET' ? {} : { body: new Uint8Array(Buffer.concat(chunks)) }),
        }),
      );
      response.writeHead(result.status, Object.fromEntries(result.headers));
      if (result.body)
        Readable.fromWeb(result.body as import('node:stream/web').ReadableStream).pipe(response);
      else response.end();
    } catch {
      response.writeHead(500);
      response.end();
    }
  });
  try {
    const db = fixture.db;
    await initializeDatabase(db);
    const now = Date.now();
    const login = await loginFixture(db, 'http-owner', now),
      connection = await connectionFixture(db, login.ownerId, 'TEAM123');
    const device = await deviceFixture(db, login.ownerId, connection.id, 'Phone', '18.0');
    const objects = new PersonalObjects(db, directory, () => now, {
      maxFile: 1024,
      ownerQuota: 8192,
      globalQuota: 16384,
      minimumFree: 0,
      retentionMs: 86400000,
    });
    await objects.recover();
    const service = new Service(db, { now: () => now });
    const jobs = new JobsActions(
      db,
      () => now,
      async () => {},
    );
    const storage = new PersonalStorage(objects);
    const artifacts = new PersonalArtifacts(objects);
    const receive = new ReceiveUpload(db, storage, jobs);
    state.app = {
      service,
      jobs,
      receiveUpload: receive.run.bind(receive),
      jobRequests: new JobRequests(db, jobs),
      authorization: new RequestAuthorization(db, () => now),
      lifecycle: new RequestLifecycle(service, jobs, storage, artifacts),
      history: new InstallationHistory(db, () => now),
      queries: new RuntimeQueries(db, () => now),
      capabilities: { runner: true },
      devices: {},
      catalogs: {},
      collections: {},
    };
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const address = server.address();
    if (!address || typeof address === 'string') throw Error('PORT_UNAVAILABLE');
    state.origin = 'http://localhost:' + address.port;
    const headers = {
      'content-type': 'application/json',
      cookie: '__Host-isign-session=' + login.token,
      'x-isign-csrf': login.csrf,
      origin: state.origin,
    };
    expect((await fetch(state.origin + '/api/session')).status).toBe(401);
    expect(
      (
        await fetch(state.origin + '/api/uploads', {
          method: 'POST',
          headers: { ...headers, origin: 'https://foreign.invalid' },
          body: '{}',
        })
      ).status,
    ).toBe(403);
    const admitted = await fetch(state.origin + '/api/uploads', {
      method: 'POST',
      headers,
      body: JSON.stringify({ name: 'HTTP.ipa', key: 'http', deviceId: device.id }),
    });
    expect(admitted.status).toBe(201);
    const submission = await admitted.json();
    const duplicate = await fetch(state.origin + '/api/uploads', {
      method: 'POST',
      headers,
      body: JSON.stringify({ name: 'Other.ipa', key: 'second', deviceId: device.id }),
    });
    expect(duplicate.status).toBe(409);
    const received = await fetch(state.origin + '/api/uploads/' + submission.uploadId, {
      method: 'PUT',
      headers: { ...headers, 'content-type': 'application/octet-stream' },
      body: Buffer.from('synthetic input'),
    });
    expect(received.status).toBe(201);
    const library = await fetch(state.origin + '/api/library', { headers });
    expect((await library.json()).jobs[0]).toMatchObject({ id: submission.jobId, state: 'queued' });
    const cancelled = await fetch(state.origin + '/api/jobs/' + submission.jobId + '/cancel', {
      method: 'POST',
      headers,
      body: '{}',
    });
    expect(cancelled.status).toBe(200);
    expect((await db.query('SELECT state FROM jobs')).rows).toEqual([{ state: 'cancelled' }]);
    expect((await db.query('SELECT id FROM personal_objects')).rows).toHaveLength(0);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
    await fixture.close();
    await rm(directory, { recursive: true, force: true });
  }
});
