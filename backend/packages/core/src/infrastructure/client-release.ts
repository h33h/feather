import { open, type FileHandle } from 'node:fs/promises';
import { constants, type BigIntStats } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { Failure } from '../shared/errors';

import type { ClientReleaseStatus, ClientReleaseSource } from '../shared/client-release';
/** The path and pinned digest are operator configuration, never request data. */
export class LocalClientRelease {
  private readonly file?: string;
  private readonly digest?: string;
  private readonly version?: string;
  private readonly problem?: string;
  private readonly now: () => number;
  private cached?: { identity: string; expiresAt: number; status: ClientReleaseStatus };
  private pendingStatus?: Promise<ClientReleaseStatus>;
  constructor(env: Record<string, string | undefined>, options: { now?: () => number } = {}) {
    this.now = options.now ?? (() => performance.now());
    const file = env.ISIGN_CLIENT_IPA_PATH,
      digest = env.ISIGN_CLIENT_IPA_SHA256,
      version = env.ISIGN_CLIENT_VERSION;
    if (!file && !digest) this.problem = 'CLIENT_RELEASE_NOT_CONFIGURED';
    else if (
      !file ||
      !path.isAbsolute(file) ||
      path.normalize(file) !== file ||
      !digest ||
      !/^[a-fA-F0-9]{64}$/.test(digest) ||
      (version !== undefined &&
        (!version.trim() || version.length > 100 || /[\x00-\x1f\x7f]/.test(version)))
    )
      this.problem = 'CLIENT_RELEASE_INVALID';
    else {
      this.file = file;
      this.digest = digest.toLowerCase();
      this.version = version;
    }
  }
  private identity(stat: BigIntStats) {
    if (!stat.isFile() || stat.size < 1n || stat.size > BigInt(1024 ** 3))
      throw new Failure('CLIENT_RELEASE_UNAVAILABLE', 503);
    return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].join(':');
  }
  private async openFile() {
    if (this.problem) throw new Failure(this.problem, 503);
    const handle = await open(this.file!, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      return { handle, identity: this.identity(await handle.stat({ bigint: true })) };
    } catch (error) {
      await handle.close();
      throw error;
    }
  }
  private async *read(handle: FileHandle, identity: string): AsyncGenerator<Uint8Array> {
    const hash = createHash('sha256');
    let size = 0;
    for await (const part of handle.createReadStream({ autoClose: false })) {
      const bytes = part as Buffer;
      size += bytes.length;
      if (size > 1024 ** 3) throw new Failure('CLIENT_RELEASE_UNAVAILABLE', 503);
      hash.update(bytes);
      yield bytes;
    }
    if (this.identity(await handle.stat({ bigint: true })) !== identity)
      throw new Failure('CLIENT_RELEASE_UNAVAILABLE', 503);
    if (hash.digest('hex') !== this.digest)
      throw new Failure('CLIENT_RELEASE_CHECKSUM_MISMATCH', 503);
  }
  private unavailable(error: unknown): ClientReleaseStatus {
    return {
      name: 'iSign Client',
      available: false,
      reason: error instanceof Failure ? error.code : 'CLIENT_RELEASE_UNAVAILABLE',
    };
  }
  private async *bytes(): AsyncGenerator<Uint8Array> {
    let source;
    try {
      source = await this.openFile();
      yield* this.read(source.handle, source.identity);
    } catch (error) {
      throw new Failure(this.unavailable(error).reason!, 503);
    } finally {
      await source?.handle.close();
    }
  }
  private async inspectStatus(): Promise<ClientReleaseStatus> {
    let source;
    try {
      // Open and fstat on every inspection: a warm cache cannot mask path replacement or symlinks.
      source = await this.openFile();
      if (this.cached?.identity === source.identity && this.cached.expiresAt > this.now())
        return { ...this.cached.status };
      let status: ClientReleaseStatus;
      try {
        for await (const chunk of this.read(source.handle, source.identity)) void chunk;
        status = {
          name: 'iSign Client',
          available: true,
          ...(this.version ? { version: this.version } : {}),
        };
      } catch (error) {
        status = this.unavailable(error);
      }
      if (this.identity(await source.handle.stat({ bigint: true })) !== source.identity)
        return this.unavailable(new Failure('CLIENT_RELEASE_UNAVAILABLE', 503));
      this.cached = {
        identity: source.identity,
        expiresAt: this.now() + 5000,
        status: { ...status },
      };
      return status;
    } catch (error) {
      return this.unavailable(error);
    } finally {
      await source?.handle.close();
    }
  }
  status(): Promise<ClientReleaseStatus> {
    return (this.pendingStatus ??= this.inspectStatus().finally(() => {
      this.pendingStatus = undefined;
    }));
  }
  async open(): Promise<ClientReleaseSource> {
    // Admission and the later upload each verify the complete source, independent of public status.
    for await (const chunk of this.bytes()) void chunk;
    return {
      digest: this.digest!,
      ...(this.version ? { version: this.version } : {}),
      bytes: this.bytes(),
    };
  }
}
