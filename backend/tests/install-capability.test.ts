import { expect, it } from 'vitest';
import { Readable } from 'node:stream';
import { createDatabase } from './helpers/database';
import { Tickets } from '../packages/core/src/library/tickets';
import { ConnectionLifecycle } from '../packages/core/src/apple/connection-lifecycle';
import { guardedDownload } from '../packages/core/src/library/guarded-download';
async function fixture(
  deviceCheck?: (owner: string, device: string, force: boolean) => Promise<void>,
) {
  const db = await createDatabase();
  await db.query("INSERT INTO users(id,login_name,created_at) VALUES('o','owner',1)");
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('c','o','TEAM123','ready','asc')",
  );
  await db.query(
    "INSERT INTO user_apple_bindings(user_id,connection_id,connection_owner_id) VALUES('o','c','o')",
  );
  await db.query(
    "INSERT INTO devices(id,owner_id,connection_id,connection_owner_id,name,status,connection_generation,enrollment_verified_at) VALUES('d','o','c','o','Phone','ready',1,1)",
  );
  await db.query(
    "INSERT INTO uploads(id,owner_id,name,object_key,size,digest,status,created_at,expires_at) VALUES('u','o','App.ipa','u.ipa',1,'digest','expired',1,1)",
  );
  await db.query(
    "INSERT INTO jobs(id,owner_id,upload_id,device_id,connection_id,connection_owner_id,connection_generation,state,idempotency_key,created_at,updated_at,finished_at) VALUES('j','o','u','d','c','o',1,'ready','key',1000,1000,1000)",
  );
  await db.query(
    "INSERT INTO artifacts(id,owner_id,job_id,connection_id,connection_owner_id,device_id,object_key,digest,metadata,valid_until,created_at,ready_at,expires_at,verified) VALUES('a','o','j','c','o','d','a.ipa','digest','{\"generation\":1}',9999999,1000,1000,1801000,true)",
  );
  let now = 1501000;
  return {
    db,
    tickets: new Tickets(db, () => now, deviceCheck),
    setNow(value: number) {
      now = value;
    },
  };
}
it('does not extend the result deadline and can reopen a capability without cookies', async () => {
  const { db, tickets, setNow } = await fixture();
  const link = await tickets.issueDetails('o', 'a');
  expect(link.expiresAt).toBe(1801000);
  expect((await tickets.resolve(link.ticket)).id).toBe('a');
  expect((await tickets.resolve(link.ticket)).id).toBe('a');
  expect((await db.query('SELECT id FROM audit')).rows).toHaveLength(0);
  setNow(1801000);
  await expect(tickets.resolve(link.ticket)).rejects.toThrow('NOT_FOUND');
});
it('checks live ticket and artifact authority in two streaming queries', async () => {
  const { db } = await fixture();
  let queries = 0;
  const tickets = new Tickets(
    {
      ...db,
      query: async <T>(sql: string, params?: unknown[]) => {
        queries++;
        return db.query<T>(sql, params);
      },
    },
    () => 1501000,
  );
  const cap = await tickets.issue('o', 'a');
  const transfer = await tickets.beginTransfer(cap);
  queries = 0;
  expect((await transfer.check()).id).toBe('a');
  expect(queries).toBe(2);
});
it.each([
  "UPDATE tickets SET state='revoked'",
  "UPDATE users SET blocked_at=1501000 WHERE id='o'",
  "UPDATE devices SET connection_generation=2 WHERE id='d'",
  "UPDATE devices SET enrollment_verified_at=NULL WHERE id='d'",
])('rechecks authority after device validation runs %s', async (change) => {
  let mutate: (() => Promise<unknown>) | undefined;
  const { db, tickets } = await fixture(async () => {
    await mutate?.();
  });
  const cap = await tickets.issue('o', 'a');
  const transfer = await tickets.beginTransfer(cap);
  mutate = () => db.query(change);
  await expect(transfer.check()).rejects.toThrow('NOT_FOUND');
});
it('does not release pending file bytes after ticket revocation', async () => {
  const { db, tickets } = await fixture();
  const cap = await tickets.issue('o', 'a');
  const transfer = await tickets.beginTransfer(cap);
  let entered!: () => void, release!: () => void;
  const reading = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const blocked = new Promise<void>((resolve) => {
    release = resolve;
  });
  const source = Readable.from(
    (async function* () {
      entered();
      await blocked;
      yield Buffer.from('private IPA bytes');
    })(),
  );
  let closed = false;
  const body = guardedDownload({
    source,
    close: async () => {
      closed = true;
    },
    check: transfer.check,
    expiresAt: 1801000,
    now: () => 1501000,
  });
  const pending = body.getReader().read();
  await reading;
  await db.query("UPDATE tickets SET state='revoked'");
  release();
  await expect(pending).rejects.toThrow('NOT_FOUND');
  expect(source.destroyed).toBe(true);
  expect(closed).toBe(true);
});
it('does not follow a ticket rebound to a different artifact during a transfer', async () => {
  const { db, tickets } = await fixture();
  const cap = await tickets.issue('o', 'a');
  const transfer = await tickets.beginTransfer(cap);
  await db.query(`INSERT INTO artifacts(id,owner_id,job_id,connection_id,connection_owner_id,device_id,object_key,digest,metadata,valid_until,created_at,expires_at,verified,ready_at)
    SELECT 'b',owner_id,job_id,connection_id,connection_owner_id,device_id,'b.ipa',digest,metadata,valid_until,created_at,expires_at,verified,ready_at FROM artifacts WHERE id='a'`);
  await db.query("UPDATE tickets SET artifact_id='b'");
  await expect(transfer.check()).rejects.toThrow('NOT_FOUND');
});
it('closes an existing capability immediately when its connection is disconnected', async () => {
  const { db, tickets } = await fixture();
  const link = await tickets.issueDetails('o', 'a');
  await new ConnectionLifecycle(db, () => 1501000, {
    fresh: async () => ({ ownerId: 'o' }),
  }).disconnect('', '', '', '');
  await expect(tickets.resolve(link.ticket)).rejects.toThrow('NOT_FOUND');
});
it.each([
  "UPDATE users SET blocked_at=1501000 WHERE id='o'",
  "UPDATE devices SET enrollment_verified_at=NULL WHERE id='d'",
  "UPDATE devices SET connection_generation=2 WHERE id='d'",
  "UPDATE devices SET access_grant_generation=2 WHERE id='d'",
  "UPDATE connections SET generation=2 WHERE id='c'",
  "UPDATE artifacts SET verified=false WHERE id='a'",
  "UPDATE artifacts SET expires_at=1501000 WHERE id='a'",
  "UPDATE jobs SET state='failed' WHERE id='j'",
  "UPDATE tickets SET state='revoked'",
])('rechecks download authority between chunks after %s', async (change) => {
  const { db, tickets } = await fixture();
  const cap = await tickets.issue('o', 'a');
  const transfer = await tickets.beginTransfer(cap);
  await transfer.check();
  await db.query(change);
  await expect(transfer.check()).rejects.toThrow('NOT_FOUND');
});
