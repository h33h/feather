// Browser contracts share their DTO ownership with the server.
export {
  appleSchema,
  devicesSchema,
  sessionSchema,
  type AppleData,
  type AuthSession,
  type DeviceData,
} from '../../../../backend/packages/contracts/src/index';
export type Api = (
  path: string,
  data?: unknown,
) => Promise<{
  profileXml?: string;
  expiresAt?: number;
  installUrl?: string;
  handoffUrl?: string;
  qrSvg?: string;
  [key: string]: unknown;
}>;
export type Action = (fn: () => Promise<void>) => Promise<void>;
