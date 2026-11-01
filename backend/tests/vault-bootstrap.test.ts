import { describe, expect, it, vi } from 'vitest';
import { DatabaseBootstrapPort } from '../packages/core/src/apple/bootstrap-store';
import { createDatabase } from './helpers/database';
import { Vault, type Kms } from '../packages/core/src/apple/vault';
async function fixture() {
  const db = await createDatabase();
  let now = 10000;
  await db.query(
    "INSERT INTO users(id,login_name,created_at) VALUES('owner','owner@example.test',0),('foreign','foreign@example.test',0)",
  );
  await db.query(
    "INSERT INTO connections(id,owner_id,team_id,state,provider) VALUES('connection','owner','pending:connection','validating','asc'),('foreign-connection','foreign','pending:foreign','validating','asc')",
  );
  const keys = new Map<string, Buffer>();
  let generated: Buffer | undefined;
  let unwrapped: Buffer | undefined;
  let generateHook: (() => Promise<void>) | undefined;
  let unwrapHook: (() => Promise<void>) | undefined;
  let sequence = 0;
  const kms: Kms = {
    generate: vi.fn(async () => {
      generated = Buffer.alloc(32, 7);
      const wrapped = 'synthetic-' + ++sequence;
      keys.set(wrapped, Buffer.from(generated));
      await generateHook?.();
      return { plaintext: generated, wrapped };
    }),
    unwrap: vi.fn(async (wrapped) => {
      unwrapped = Buffer.from(keys.get(wrapped)!);
      await unwrapHook?.();
      return unwrapped;
    }),
  };
  const vault = new Vault(db, kms, () => now);
  const bootstrap = new DatabaseBootstrapPort({
    db,
    now: () => now,
    prepareIdentity: async () => {
      throw Error('unused');
    },
    findCertificates: async () => [],
    createCertificate: async () => {
      throw Error('unused');
    },
  });
  return {
    db,
    vault,
    kms,
    bootstrap,
    advance: (value: number) => {
      now += value;
    },
    generated: () => generated,
    unwrapped: () => unwrapped,
    setGenerateHook: (hook: () => Promise<void>) => {
      generateHook = hook;
    },
    setUnwrapHook: (hook: () => Promise<void>) => {
      unwrapHook = hook;
    },
  };
}
describe('Vault ASC connection and bootstrap access', () => {
  it('permits validating p8 but forbids ordinary pending distribution keys and deleted users', async () => {
    const f = await fixture();
    try {
      await expect(
        f.vault.seal('owner', 'connection', 'distribution-key', Buffer.from('synthetic')),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      expect(f.kms.generate).not.toHaveBeenCalled();
      const p8 = await f.vault.seal('owner', 'connection', 'p8', Buffer.from('synthetic-p8'));
      expect(p8).toBeTruthy();
      expect(f.generated()).toEqual(Buffer.alloc(32));
      await f.db.query("UPDATE users SET deleted_at=1 WHERE id='owner'");
      await expect(
        f.vault.seal('owner', 'connection', 'p8', Buffer.from('synthetic')),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      expect(f.kms.generate).toHaveBeenCalledTimes(1);
    } finally {
      await f.db.close();
    }
  });
  it('opens only the attached current-owner/generation ready ASC p8', async () => {
    const f = await fixture();
    try {
      const secret = await f.vault.seal('owner', 'connection', 'p8', Buffer.from('synthetic-p8'));
      await f.db.query(
        "UPDATE connections SET secret_ref=$1,state='ready',team_id='SYNTHETIC1' WHERE id='connection'",
        [secret],
      );
      const plaintext = await f.vault.openForConnection('owner', 'connection', 1);
      expect(plaintext.toString()).toBe('synthetic-p8');
      plaintext.fill(0);
      expect(f.unwrapped()).toEqual(Buffer.alloc(32));
      await expect(f.vault.openForConnection('foreign', 'connection', 1)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      await expect(f.vault.openForConnection('owner', 'connection', 2)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      expect(f.kms.unwrap).toHaveBeenCalledTimes(1);
    } finally {
      await f.db.close();
    }
  });
  it('rechecks generation/disconnect after KMS unwrap and zeros the returned key', async () => {
    const f = await fixture();
    try {
      const secret = await f.vault.seal('owner', 'connection', 'p8', Buffer.from('synthetic-p8'));
      await f.db.query(
        "UPDATE connections SET secret_ref=$1,state='ready',team_id='SYNTHETIC1' WHERE id='connection'",
        [secret],
      );
      f.setUnwrapHook(async () => {
        await f.db.query(
          "UPDATE connections SET generation=generation+1,state='disconnected' WHERE id='connection'",
        );
      });
      await expect(f.vault.openForConnection('owner', 'connection', 1)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      expect(f.unwrapped()).toEqual(Buffer.alloc(32));
    } finally {
      await f.db.close();
    }
  });
  it('rejects disconnected generation after KMS generation without persisting ciphertext', async () => {
    const f = await fixture();
    try {
      f.setGenerateHook(async () => {
        await f.db.query(
          "UPDATE connections SET generation=generation+1,state='disconnected' WHERE id='connection'",
        );
      });
      await expect(
        f.vault.seal('owner', 'connection', 'p8', Buffer.from('synthetic')),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      expect((await f.db.query('SELECT id FROM secrets')).rows).toHaveLength(0);
      expect(f.generated()).toEqual(Buffer.alloc(32));
    } finally {
      await f.db.close();
    }
  });
  it('allows distribution-key and p8 only under a live exact bootstrap lease', async () => {
    const f = await fixture();
    try {
      const lease = await f.bootstrap.acquire('owner', 'connection', 1);
      const secret = await f.vault.sealForBootstrap(
        lease,
        'distribution-key',
        Buffer.from('synthetic-distribution'),
      );
      const p8 = await f.vault.sealForBootstrap(lease, 'p8', Buffer.from('synthetic-p8'));
      const plaintext = await f.vault.openForBootstrap(lease, secret, 'distribution-key');
      expect(plaintext.toString()).toBe('synthetic-distribution');
      plaintext.fill(0);
      const apiKey = await f.vault.openForBootstrap(lease, p8, 'p8');
      expect(apiKey.toString()).toBe('synthetic-p8');
      apiKey.fill(0);
      await expect(
        f.vault.openForBootstrap({ ...lease, ownerId: 'foreign' }, secret),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      await expect(f.vault.openForBootstrap({ ...lease, nonce: 'stale' }, secret)).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      await expect(
        f.vault.openForBootstrap({ ...lease, expiresAt: lease.expiresAt + 1 }, secret),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      await expect(f.vault.openForBootstrap(lease, secret, 'p8')).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      await expect(
        f.vault.sealForBootstrap(lease, 'catalog-auth' as 'p8', Buffer.from('synthetic')),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      expect(f.kms.unwrap).toHaveBeenCalledTimes(2);
    } finally {
      await f.db.close();
    }
  });
  it('fences expired/replaced bootstrap leases before reads and after asynchronous unwrap', async () => {
    const f = await fixture();
    try {
      const lease = await f.bootstrap.acquire('owner', 'connection', 1);
      const secret = await f.vault.sealForBootstrap(
        lease,
        'distribution-key',
        Buffer.from('synthetic'),
      );
      f.setUnwrapHook(async () => {
        await f.db.query(
          "UPDATE bootstrap_operations SET nonce='replacement' WHERE owner_id='owner'",
        );
      });
      await expect(f.vault.openForBootstrap(lease, secret)).rejects.toThrow('SECRET_UNAVAILABLE');
      expect(f.unwrapped()).toEqual(Buffer.alloc(32));
      f.advance(900001);
      await expect(f.vault.sealForBootstrap(lease, 'p8', Buffer.from('synthetic'))).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
      await expect(f.vault.openForBootstrap(lease, secret)).rejects.toThrow('SECRET_UNAVAILABLE');
      expect(f.kms.unwrap).toHaveBeenCalledTimes(1);
    } finally {
      await f.db.close();
    }
  });
  it('checks pending ASC state and a current bootstrap nonce again before secret insertion', async () => {
    const f = await fixture();
    try {
      const lease = await f.bootstrap.acquire('owner', 'connection', 1);
      f.setGenerateHook(async () => {
        await f.db.query(
          "UPDATE bootstrap_operations SET nonce='replacement' WHERE owner_id='owner'",
        );
      });
      await expect(
        f.vault.sealForBootstrap(lease, 'distribution-key', Buffer.from('synthetic')),
      ).rejects.toThrow('SECRET_UNAVAILABLE');
      expect((await f.db.query('SELECT id FROM secrets')).rows).toHaveLength(0);
      expect(f.generated()).toEqual(Buffer.alloc(32));
      const replaced = { ...lease, nonce: 'replacement' };
      await f.db.query("UPDATE connections SET state='ready' WHERE id='connection'");
      await expect(f.vault.openForBootstrap(replaced, 'missing')).rejects.toThrow(
        'SECRET_UNAVAILABLE',
      );
    } finally {
      await f.db.close();
    }
  });
});
it('blocking the owner fences an acquired bootstrap lease before the next operation', async () => {
  const f = await fixture();
  try {
    const lease = await f.bootstrap.acquire('owner', 'connection', 1);
    await f.db.query("UPDATE users SET blocked_at=1 WHERE id='owner'");
    await expect(f.bootstrap.assertCurrent(lease)).rejects.toThrow('STALE_BOOTSTRAP_LEASE');
  } finally {
    await f.db.close();
  }
});
