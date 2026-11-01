import { expect, it } from 'vitest';
import { createServer, type RequestListener } from 'node:http';
import { once } from 'node:events';
import { Client, request } from 'undici';
import { createHmac } from 'node:crypto';
import {
  requestBrokerTransport,
  ScopedBrokerRpc,
} from '../packages/core/src/infrastructure/broker-rpc';
import type { ProductionPipelineConfig } from '../packages/core/src/composition/signing-runtime';
import { HttpRunnerProvider } from '../packages/core/src/infrastructure/runner-http';
import { canonicalReport } from '../packages/core/src/shared/canonical-json';

async function fixture(handler: RequestListener) {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw Error('TEST_SERVER_REQUIRED');
  const origin = 'http://127.0.0.1:' + address.port;
  const client = new Client(origin, { headersTimeout: 20, bodyTimeout: 2000 });
  const transport = requestBrokerTransport((url, options) =>
    request(url, { ...options, dispatcher: client }),
  );
  return {
    server,
    transport,
    origin,
    close: async () => {
      await client.destroy();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

it('waits for legitimate compute headers beyond the client default timeout', async () => {
  const f = await fixture((_req, res) => {
    setTimeout(() => res.end('signed'), 1500);
  });
  try {
    const response = await f.transport.request({
      url: f.origin + '/v1/instances/test/execute',
      method: 'POST',
      headers: {},
      body: '{}',
      signal: AbortSignal.timeout(5000),
    });
    let text = '';
    for await (const chunk of response.body) text += Buffer.from(chunk).toString();
    expect(response.status).toBe(200);
    expect(text).toBe('signed');
  } finally {
    await f.close();
  }
});

it('still aborts a compute wait at the caller deadline and closes the socket', async () => {
  let disconnected!: () => void;
  const closed = new Promise<void>((resolve) => {
    disconnected = resolve;
  });
  const f = await fixture((_req, res) => {
    res.on('close', disconnected);
  });
  try {
    await expect(
      f.transport.request({
        url: f.origin + '/v1/instances/test/execute',
        method: 'POST',
        headers: {},
        body: '{}',
        signal: AbortSignal.timeout(60),
      }),
    ).rejects.toMatchObject({ name: 'TimeoutError' });
    await closed;
  } finally {
    await f.close();
  }
});

it('streams the source and response and releases an abandoned response', async () => {
  let uploaded = '';
  let disconnected!: () => void;
  const closed = new Promise<void>((resolve) => {
    disconnected = resolve;
  });
  const f = await fixture(async (req, res) => {
    for await (const chunk of req) uploaded += chunk.toString();
    res.on('close', disconnected);
    res.write('first');
  });
  try {
    async function* source() {
      yield Buffer.from('one');
      yield Buffer.from('two');
    }
    const result = await f.transport.request({
      url: f.origin + '/v1/instances/test/source',
      method: 'POST',
      headers: {},
      body: source(),
      signal: AbortSignal.timeout(5000),
    });
    for await (const chunk of result.body) {
      expect(Buffer.from(chunk).toString()).toBe('first');
      break;
    }
    await closed;
    expect(uploaded).toBe('onetwo');
  } finally {
    await f.close();
  }
});

it('never follows broker redirects and closes a rejected response', async () => {
  let redirected = false;
  let disconnected!: () => void;
  const closed = new Promise<void>((resolve) => {
    disconnected = resolve;
  });
  const f = await fixture((req, res) => {
    if (req.url === '/redirected') redirected = true;
    res.on('close', disconnected);
    res.writeHead(302, { location: '/redirected' });
    res.write('rejected');
  });
  try {
    const result = await f.transport.request({
      url: f.origin + '/v1/control/test',
      method: 'POST',
      headers: { authorization: 'Bearer synthetic' },
      body: '{}',
      signal: AbortSignal.timeout(5000),
    });
    expect(result.status).toBe(302);
    await closed;
    expect(redirected).toBe(false);
  } finally {
    await f.close();
  }
});

it('preserves a bounded semantic rejection while closing an active source upload', async () => {
  let returned!: () => void;
  const sourceClosed = new Promise<void>((resolve) => {
    returned = resolve;
  });
  const f = await fixture((_req, res) => {
    res.writeHead(422, { 'content-type': 'application/json' });
    res.end('{"error":"SOURCE_LIMIT"}');
  });
  async function* source() {
    try {
      for (;;) {
        yield Buffer.alloc(4096);
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    } finally {
      returned();
    }
  }
  try {
    const response = await f.transport.request({
      url: f.origin + '/v1/instances/test/source',
      method: 'POST',
      headers: {},
      body: source(),
      signal: AbortSignal.timeout(5000),
    });
    let body = '';
    for await (const chunk of response.body) body += Buffer.from(chunk).toString();
    expect(response.status).toBe(422);
    expect(JSON.parse(body)).toEqual({ error: 'SOURCE_LIMIT' });
    await sourceClosed;
  } finally {
    await f.close();
  }
});

it('bounds a rejected response and closes its socket', async () => {
  let disconnected!: () => void;
  const closed = new Promise<void>((resolve) => {
    disconnected = resolve;
  });
  const f = await fixture((_req, res) => {
    res.on('close', disconnected);
    res.writeHead(422);
    res.write(Buffer.alloc(64 * 1024 + 1));
  });
  try {
    await expect(
      f.transport.request({
        url: f.origin + '/v1/instances/test/source',
        method: 'POST',
        headers: {},
        body: '{}',
        signal: AbortSignal.timeout(5000),
      }),
    ).rejects.toThrow('RUNNER_RESPONSE_TOO_LARGE');
    await closed;
  } finally {
    await f.close();
  }
});

it('closes an abandoned control response after its body exceeds the limit', async () => {
  let disconnected!: () => void;
  const closed = new Promise<void>((resolve) => {
    disconnected = resolve;
  });
  const f = await fixture((_req, res) => {
    res.on('close', disconnected);
    res.write(Buffer.alloc(4 * 1024 ** 2 + 1));
  });
  const rpc = new ScopedBrokerRpc({
    endpoint: f.origin,
    transport: f.transport,
    token: 't'.repeat(32),
    audience: 'test',
    proofKey: Buffer.alloc(32),
  } as ProductionPipelineConfig);
  try {
    await expect(rpc.call('synthetic', {}, {})).rejects.toThrow('RUNNER_RESPONSE_TOO_LARGE');
    await closed;
  } finally {
    await f.close();
  }
});

it('carries a real HTTP analyzer rejection through the provider as a public failure', async () => {
  const proofKey = Buffer.alloc(32, 1);
  const f = await fixture(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += chunk.toString();
    if (req.url === '/v1/instances') {
      const payload = JSON.parse(raw);
      const report = {
        id: 'vm',
        ownerId: 'o',
        jobId: 'j',
        nonce: payload.nonce,
        audience: 'test',
        disposable: true,
        expiresAt: Date.now() + 60000,
      };
      res.end(
        JSON.stringify({
          report,
          attestation: createHmac('sha256', proofKey).update(canonicalReport(report)).digest('hex'),
        }),
      );
    } else if (req.url?.endsWith('/source')) {
      res.writeHead(204).end();
    } else {
      res
        .writeHead(422, { 'content-type': 'application/json' })
        .end('{"error":"ENTITLEMENTS_INVALID"}');
    }
  });
  const signal = AbortSignal.timeout(5000);
  const provider = new HttpRunnerProvider({
    endpoint: 'https://runner.synthetic.invalid',
    token: 't'.repeat(32),
    audience: 'test',
    proofKey,
    transport: {
      request: (input) =>
        f.transport.request({
          ...input,
          url: input.url.replace('https://runner.synthetic.invalid', f.origin),
        }),
    },
  });
  try {
    const vm = await provider.launch({
      ownerId: 'o',
      jobId: 'j',
      maxRuntimeMs: 60000,
      maxInputBytes: 1024,
      maxUnpackedBytes: 2048,
      maxEntries: 10,
      signal,
    });
    const grant = {
      ownerId: 'o',
      jobId: 'j',
      leaseToken: 'lease',
      connectionId: 'connection',
      connectionGeneration: 1,
      deviceId: 'device',
      uploadDigest: 'a'.repeat(64),
      taskNonce: 'nonce',
      isolationInstanceId: 'vm',
      expiresAt: Date.now() + 30000,
    };
    await expect(
      vm.analyze({
        grant,
        source: (async function* () {
          yield Buffer.from('IPA');
        })(),
        signal,
      }),
    ).rejects.toMatchObject({ code: 'ENTITLEMENTS_INVALID', status: 422 });
  } finally {
    await f.close();
  }
});

it('aborts a streamed source and closes its iterator', async () => {
  let returned!: () => void;
  const sourceClosed = new Promise<void>((resolve) => {
    returned = resolve;
  });
  const f = await fixture((req) => {
    req.resume();
  });
  async function* source() {
    try {
      for (;;) {
        yield Buffer.alloc(4096);
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    } finally {
      returned();
    }
  }
  try {
    await expect(
      f.transport.request({
        url: f.origin + '/v1/instances/test/source',
        method: 'POST',
        headers: {},
        body: source(),
        signal: AbortSignal.timeout(60),
      }),
    ).rejects.toMatchObject({ name: 'TimeoutError' });
    await sourceClosed;
  } finally {
    await f.close();
  }
});
