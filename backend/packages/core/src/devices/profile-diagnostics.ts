import { randomUUID } from 'node:crypto';
import { mkdir, chmod, readdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Database } from '../shared/database';
import { hash } from '../shared/index';
/** Temporary operator-only diagnostics, never exposed in a browser response. */
export class ProfileDiagnostics {
  private writing = false;
  constructor(
    private db: Database,
    private now: () => number,
    private directory: string,
  ) {}
  async capture(challenge: string, body: Buffer, code: string) {
    if (
      this.writing ||
      code !== 'INVALID_DEVICE_CALLBACK' ||
      !body.length ||
      body.length > 65536 ||
      !/^[A-Za-z0-9_-]{43}$/.test(challenge)
    )
      return false;
    this.writing = true;
    try {
      const owner = (
        await this.db.query<{
          owner_id: string;
        }>(
          `SELECT c.owner_id FROM device_collection_challenges c JOIN sessions s ON s.token_hash=c.session_hash AND s.owner_id=c.owner_id JOIN users u ON u.id=c.owner_id WHERE c.token_hash=$1 AND c.consumed_at IS NULL AND c.expires_at>$2 AND s.expires_at>$2 AND u.deleted_at IS NULL`,
          [hash(challenge), this.now()],
        )
      ).rows[0];
      if (!owner) return false;
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      await chmod(this.directory, 0o700);
      const files = (await readdir(this.directory))
        .filter((name) => /^\d+-[a-f0-9]{12}-[a-f0-9-]{36}\.cms$/.test(name))
        .sort();
      for (const [index, file] of files.entries())
        if (Number(file.split('-')[0]) < this.now() - 900000 || index < files.length - 2)
          await rm(join(this.directory, file), { force: true });
      await writeFile(
        join(
          this.directory,
          this.now() + '-' + hash(owner.owner_id).slice(0, 12) + '-' + randomUUID() + '.cms',
        ),
        body,
        { mode: 0o600, flag: 'wx' },
      );
      return true;
    } finally {
      this.writing = false;
    }
  }
}
