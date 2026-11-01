import type { ExecutorGrant, VerifiedReport } from '../shared/runner-contracts';
export interface DisposableExecutor {
  id: string;
  expiresAt?: number;
  execute(input: { grant: ExecutorGrant; task: unknown; signal: AbortSignal }): Promise<{
    report: VerifiedReport;
    attestation: string;
    body: AsyncIterable<Uint8Array>;
  }>;
  destroy(): Promise<void>;
}
/** Deployment adapter must authenticate a fresh disposable VM; a tempdir is never an executor. */
export interface ExecutorProvider {
  launch(input: {
    ownerId: string;
    jobId: string;
    launchNonce?: string;
    signal: AbortSignal;
    maxRuntimeMs: number;
    maxInputBytes: number;
    maxUnpackedBytes: number;
    maxEntries: number;
  }): Promise<DisposableExecutor>;
  retireLaunch?(nonce: string): Promise<void>;
  verifyInstance(instance: DisposableExecutor): Promise<boolean>;
}
