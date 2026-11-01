import type { Readable } from 'node:stream';
export type UploadOptions = {
  uploadId?: string;
  jobId?: string;
  expectedDigest?: string;
  provenance?: unknown;
  signal?: AbortSignal;
  selection?: {
    sourceId: string;
    releaseId: string;
    snapshot: string;
  };
  importId?: string;
  importToken?: string;
};
export interface FileReadHandle {
  stat(): Promise<{
    size: number;
  }>;
  createReadStream(options?: { start?: number; end?: number; autoClose?: boolean }): Readable;
  close(): Promise<void>;
}
export interface StoragePort {
  upload(
    ownerId: string,
    name: string,
    input: AsyncIterable<Uint8Array>,
    options?: UploadOptions,
  ): Promise<{
    id: string;
    size: number;
    digest: string;
  }>;
  read(ownerId: string, uploadId: string): Promise<FileReadHandle>;
  recoverInterrupted(): Promise<void>;
  cleanup(): Promise<void>;
}
