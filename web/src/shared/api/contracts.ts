// Compatibility entrypoint for browser consumers. DTO ownership is neutral.
export * from '../../../../backend/packages/contracts/src/index';
export type Api = (
  path: string,
  data?: unknown,
  options?: { method?: 'POST' | 'PUT' | 'DELETE' },
) => Promise<{
  profileXml?: string;
  expiresAt?: number;
  installUrl?: string;
  handoffUrl?: string;
  qrSvg?: string;
  [key: string]: unknown;
}>;
export type Action = (fn: () => Promise<void>) => Promise<void>;
