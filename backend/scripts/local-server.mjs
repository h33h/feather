import { createServer } from 'node:http';
import { once } from 'node:events';
import { parseArgs } from 'node:util';
import next from 'next';

const { values } = parseArgs({
  options: {
    port: { type: 'string', default: process.env.PORT ?? '3000' },
    hostname: { type: 'string', default: '127.0.0.1' },
  },
});
const port = Number(values.port);
const hostname = values.hostname;
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('INVALID_PORT');
process.env.ISIGN_RUNTIME = 'personal';
process.env.ISIGN_ORIGIN ??=
  'http://' + (['127.0.0.1', '::1'].includes(hostname) ? 'localhost' : hostname) + ':' + port;
process.env.NEXT_MANUAL_SIG_HANDLE = 'true';
const app = next({
  dev: true,
  dir: 'web',
  hostname: new URL(process.env.ISIGN_ORIGIN).hostname,
  port,
});
const requests = new Set();
const upgraded = new Set();
let stopping;
const server = createServer((request, response) => {
  const work = Promise.resolve()
    .then(() => app.getRequestHandler()(request, response))
    .catch((error) => {
      console.error(error);
      if (!response.headersSent) response.writeHead(500);
      response.end();
    })
    .finally(() => requests.delete(work));
  requests.add(work);
});
server.on('upgrade', (_request, socket) => {
  if (stopping) {
    socket.destroy();
    return;
  }
  upgraded.add(socket);
  socket.once('close', () => upgraded.delete(socket));
});
async function stop() {
  const closed = server.listening
    ? new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
    : Promise.resolve();
  // HMR connections must close before awaiting server.close(), even with a browser tab open.
  for (const socket of upgraded) socket.destroy();
  await closed;
  // A disconnected client can leave its handler running after the HTTP connection closes.
  await Promise.allSettled([...requests]);
  await app.close();
  await process[Symbol.for('isign.runtime.shutdown')]?.();
}
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, () => {
    if (stopping) return;
    stopping = stop().then(
      () => process.exit(0),
      (error) => {
        console.error('LOCAL_SERVER_SHUTDOWN_FAILED', error);
        process.exit(1);
      },
    );
  });
try {
  await app.prepare();
  server.listen(port, hostname);
  await once(server, 'listening');
  console.log('Local iSign ready at ' + process.env.ISIGN_ORIGIN);
} catch (error) {
  await stop();
  throw error;
}
