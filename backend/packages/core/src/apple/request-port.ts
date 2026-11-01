/** Feature-owned Apple request capability; transport and authentication belong to the adapter. */
export interface AppleRequestPort {
  request(method: 'GET' | 'POST' | 'DELETE', resource: string, body?: unknown): Promise<unknown>;
}
