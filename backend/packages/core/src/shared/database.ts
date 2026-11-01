export interface QueryDatabase {
  query<T = Record<string, unknown>>(
    sql: string,
    params?: unknown[],
  ): Promise<{
    rows: T[];
  }>;
}
export interface Database extends QueryDatabase {
  transaction<T>(work: (tx: QueryDatabase) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}
