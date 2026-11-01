import type { QueryDatabase } from '../shared/database';
import type { UploadOptions, StoragePort } from '../library/storage-contract';
import { Failure } from '../shared/errors';
type ReceiveJobs = {
  completeSource(owner: string, job: string): Promise<unknown>;
  failReceiving(owner: string, job: string, code: string): Promise<unknown>;
};
/** Storage and queue retain their transaction/lease fences; this scenario owns their ordering. */
export class ReceiveUpload {
  constructor(
    private db: QueryDatabase,
    private storage: Pick<StoragePort, 'upload'>,
    private jobs: ReceiveJobs,
  ) {}
  async run(
    owner: string,
    uploadId: string,
    input: AsyncIterable<Uint8Array>,
    signal?: AbortSignal,
    options?: Pick<UploadOptions, 'expectedDigest' | 'provenance'>,
  ) {
    const source = (
      await this.db.query<{ id: string; name: string }>(
        "SELECT j.id,u.name FROM jobs j JOIN uploads u ON u.id=j.upload_id AND u.owner_id=j.owner_id WHERE j.owner_id=$1 AND j.upload_id=$2 AND j.state='receiving'",
        [owner, uploadId],
      )
    ).rows[0];
    if (!source) throw new Failure('SOURCE_RECEIVE_UNAVAILABLE', 409);
    try {
      const upload = await this.storage.upload(owner, source.name, input, {
        uploadId,
        jobId: source.id,
        signal,
        ...options,
      });
      await this.jobs.completeSource(owner, source.id);
      return { upload, jobId: source.id };
    } catch (error) {
      await this.jobs.failReceiving(
        owner,
        source.id,
        error instanceof Failure ? error.code : 'UPLOAD_INTERRUPTED',
      );
      throw error;
    }
  }
}
