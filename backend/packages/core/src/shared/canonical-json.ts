import { Failure } from './errors';

export function canonicalReport(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean')
    return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalReport).join(',') + ']';
  if (value && typeof value === 'object')
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map(
          (k) => JSON.stringify(k) + ':' + canonicalReport((value as Record<string, unknown>)[k]),
        )
        .join(',') +
      '}'
    );
  throw new Failure('EXECUTOR_REPORT_INVALID');
}
