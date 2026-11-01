export type ExecutorGrant = {
  ownerId: string;
  connectionOwnerId?: string;
  accessGrantId?: string;
  accessGrantGeneration?: number;
  jobId: string;
  leaseToken: string;
  connectionId: string;
  connectionGeneration: number;
  deviceId: string;
  uploadDigest: string;
  taskNonce: string;
  isolationInstanceId: string;
  expiresAt: number;
  planDigest?: string;
};
export type VerifiedReport = ExecutorGrant & {
  artifactDigest: string;
  bundleId: string;
  version: string;
  title: string;
  certificateExpiresAt: number;
  profileExpiresAt: number;
  checks: {
    archive: boolean;
    components: boolean;
    signatures: boolean;
    profiles: boolean;
    device: boolean;
    entitlements: boolean;
    mapping: boolean;
  };
};
