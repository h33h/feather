import { afterEach, expect, it, vi } from 'vitest';
const state = vi.hoisted(() => ({ disconnected: false, order: [] as string[] }));
vi.mock('pg', async () => {
  const { EventEmitter } = await import('node:events');
  return {
    Pool: class extends EventEmitter {
      private client?: InstanceType<typeof EventEmitter>;
      private admin: boolean;
      constructor(options: { connectionString: string }) {
        super();
        this.admin = new URL(options.connectionString).pathname === '/isign_test';
      }
      async query(sql: string) {
        if (sql.startsWith('DROP DATABASE')) {
          state.order.push('drop');
          if (!state.disconnected) throw Error('DATABASE_CONNECTION_STILL_CLOSING');
        } else if (!this.admin && !this.client) {
          this.client = new EventEmitter();
          this.emit('connect', this.client);
        }
        return { rows: [] };
      }
      async end() {
        if (this.client) {
          const client = this.client;
          // pg-pool resolves end() before Client.end() has closed its socket.
          setImmediate(() => {
            state.disconnected = true;
            state.order.push('disconnect');
            client.emit('end');
            this.emit('remove', client);
          });
        }
      }
    },
  };
});
import { postgresFixture } from './helpers/postgres';
afterEach(() => vi.unstubAllEnvs());
it('waits for PostgreSQL client sockets before dropping a fixture database', async () => {
  vi.stubEnv('ISIGN_TEST_DATABASE_URL', 'postgresql://postgres:test@127.0.0.1/isign_test');
  const fixture = await postgresFixture();
  await fixture.db.query('SELECT 1');
  await expect(fixture.close()).resolves.toBeUndefined();
  expect(state.order).toEqual(['disconnect', 'drop']);
});
