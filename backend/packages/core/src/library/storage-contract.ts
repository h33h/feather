import type { Readable } from 'node:stream';
export type UploadOptions = {
  uploadId: string;
  jobId: string;
  signal?: AbortSignal;
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
    input: AsyncIterable<Uint8Array>,
    options: UploadOptions,
  ): Promise<{
    id: string;
    size: number;
    digest: string;
  }>;
  read(ownerId: string, uploadId: string): Promise<FileReadHandle>;
  cleanup(): Promise<void>;
}
