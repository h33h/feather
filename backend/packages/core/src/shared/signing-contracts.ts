export type SigningWarning = {
  code:
    'BUNDLE_ID_CHANGED' | 'CAPABILITY_REMOVED' | 'ENCRYPTED_EXTENSION_REMOVED' | 'MIN_OS_CORRECTED';
  componentPath: string;
  capability?: string;
  originalId?: string;
  targetId?: string;
  extensionPoint?: string;
  originalMinOs?: string;
  targetMinOs?: string;
};
export type RemovedExtension = { path: string; bundleId: string; extensionPoint: string };

export type JobMaterialEnvelope = {
  owner: string;
  connection: string;
  purpose: 'distribution-key';
  secret: string;
  aad: string;
  wrappedKey: string;
  nonce: string;
  ciphertext: string;
  tag: string;
  generation: number;
};
