import { expect, it } from 'vitest';

it('retries transient transport/provider failures but never input or authority failures', async () => {
  const { classifyJobFailure } = await import('../packages/core/src/signing/retry-policy');
  for (const code of [
    'PROVIDER_TIMEOUT',
    'PROVIDER_RATE_LIMITED',
    'RUNNER_INTERRUPTED',
    'ECONNRESET',
    'APPLE_TEMPORARY_UNAVAILABLE',
    'APPLE_RATE_LIMITED',
    'MUTATION_OUTCOME_UNKNOWN',
    'RESOURCE_RECONCILIATION_REQUIRED',
  ])
    expect(classifyJobFailure(code)).toBe('retryable');
  for (const code of [
    'DRM_UNSUPPORTED',
    'EXECUTOR_CANCELLED',
    'INVALID_P8',
    'APPLE_ACCESS_UNAVAILABLE',
    'UNKNOWN',
  ])
    expect(classifyJobFailure(code)).toBe('terminal');
});
