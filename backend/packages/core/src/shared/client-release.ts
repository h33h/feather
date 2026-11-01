export type ClientReleaseStatus = {
  name: 'iSign Client';
  available: boolean;
  version?: string;
  reason?: string;
};
export type ClientReleaseSource = {
  digest: string;
  version?: string;
  bytes: AsyncIterable<Uint8Array>;
};
export interface ClientReleasePort {
  status(): Promise<ClientReleaseStatus>;
  open(): Promise<ClientReleaseSource>;
}
