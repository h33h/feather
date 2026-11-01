import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createConnection, createServer } from 'node:net';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, expect, it } from 'vitest';

const children: ChildProcess[] = [];
const directories: string[] = [];
const declarations = path.resolve('web/next-env.d.ts');
let originalDeclarations: string;
beforeEach(async () => {
  originalDeclarations = await readFile(declarations, 'utf8');
});
afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      await exited;
    }
  }
  await Promise.all(
    directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
  );
  await writeFile(declarations, originalDeclarations);
});
async function freePort() {
  const server = createServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('PORT_UNAVAILABLE');
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}
async function start(script: string, port: number, env: Record<string, string>) {
  const args = script.includes('browser-server') ? [String(port)] : ['--port', String(port)];
  const child = spawn(process.execPath, [script, ...args], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  children.push(child);
  let output = '';
  await new Promise<void>((resolve, reject) => {
    child.stdout!.on('data', (data) => {
      output += data.toString();
      if (output.includes('Local iSign ready at')) resolve();
    });
    child.stderr!.on('data', (data) => {
      output += data.toString();
    });
    child.once('error', reject);
    child.once('exit', (code) => reject(new Error('Server exited ' + code + ': ' + output)));
  });
  return child;
}
async function stop(child: ChildProcess, signal: NodeJS.Signals) {
  const exited = once(child, 'exit');
  child.kill(signal);
  expect((await exited)[0]).toBe(0);
}
async function fixture() {
  const directory = await mkdtemp(path.join(tmpdir(), 'isign-server-safety-'));
  directories.push(directory);
  const dist = '.next-safety-' + path.basename(directory);
  directories.push(path.resolve('web', dist));
  return { env: { ISIGN_NEXT_DIST_DIR: dist } };
}
it('closes an unconfigured Next.js runtime cleanly on SIGTERM and SIGINT across restarts', async () => {
  const f = await fixture();
  const port = await freePort();
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGTERM'] as const) {
    const child = await start('backend/scripts/local-server.mjs', port, f.env);
    expect((await fetch('http://localhost:' + port + '/api/session')).status).toBe(503);
    await stop(child, signal);
  }
}, 60000);
it('runs dev and browser tests concurrently even when they inherit the same build settings', async () => {
  const f = await fixture();
  const devPort = await freePort();
  const testPort = await freePort();
  const dev = await start('backend/scripts/local-server.mjs', devPort, f.env);
  expect((await fetch('http://localhost:' + devPort + '/api/session')).status).toBe(503);
  const browser = await start('backend/scripts/browser-server.mjs', testPort, f.env);
  expect((await fetch('http://localhost:' + testPort + '/api/session')).status).toBe(503);
  expect((await fetch('http://localhost:' + devPort + '/api/session')).status).toBe(503);
  await stop(browser, 'SIGTERM');
  expect((await fetch('http://localhost:' + devPort + '/api/session')).status).toBe(503);
  await stop(dev, 'SIGTERM');
}, 60000);

it('finishes shutdown while a browser HMR WebSocket remains connected', async () => {
  const f = await fixture();
  const port = await freePort();
  const child = await start('backend/scripts/local-server.mjs', port, f.env);
  expect((await fetch('http://localhost:' + port + '/api/session')).status).toBe(503);
  const socket = createConnection(port, '127.0.0.1');
  await once(socket, 'connect');
  socket.write(
    'GET /_next/hmr HTTP/1.1\r\nHost: 127.0.0.1:' +
      port +
      '\r\nOrigin: http://localhost:' +
      port +
      '\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n',
  );
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const data = await Promise.race([
      once(socket, 'data'),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('HMR handshake did not complete')), 3000);
      }),
    ]);
    clearTimeout(timer);
    expect(data[0].toString()).toContain('101 Switching Protocols');
    const exited = once(child, 'exit');
    child.kill('SIGINT');
    const result = await Promise.race([
      exited,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('Shutdown blocked by open HMR socket')), 5000);
      }),
    ]);
    expect(result[0]).toBe(0);
  } finally {
    clearTimeout(timer);
    socket.destroy();
  }
}, 30000);

for (const order of [[0, 1], [1, 0], null]) {
  it(`restores stable Next declarations after overlapping browser servers stop ${order ? 'in order ' + order.join('-') : 'together'}`, async () => {
    const servers: ChildProcess[] = [];
    const owned: string[] = [];
    try {
      for (let i = 0; i < 2; i++) {
        const port = await freePort();
        servers.push(
          await start('backend/scripts/browser-server.mjs', port, {
            ISIGN_NEXT_DIST_DIR: '.next-safety-inherited',
          }),
        );
        const content = await readFile(declarations, 'utf8');
        const name = content.match(/(\.next-browser-[^/"\s]+)/)?.[1];
        if (!name) throw new Error('Browser build declarations not generated');
        expect(owned).not.toContain(name);
        owned.push(name);
      }
      if (order) {
        for (const index of order) await stop(servers[index], 'SIGTERM');
      } else {
        await Promise.all(servers.map((server) => stop(server, 'SIGTERM')));
      }
      const restored = await readFile(declarations, 'utf8');
      for (const name of owned) expect(restored).not.toContain(name);
      expect(restored).not.toMatch(/\.next-(?:browser|safety)-/);
    } finally {
      for (const server of servers) {
        if (server.exitCode === null && server.signalCode === null) await stop(server, 'SIGTERM');
      }
    }
  }, 60000);
}
