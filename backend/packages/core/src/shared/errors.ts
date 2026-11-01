const failureBrand = Symbol.for('isign.service.failure');
export class Failure extends Error {
  [failureBrand] = true;
  constructor(
    public code: string,
    public status = 400,
  ) {
    super(code);
  }
  static [Symbol.hasInstance](value: unknown) {
    return (
      value !== null &&
      typeof value === 'object' &&
      (value as Record<symbol, unknown>)[failureBrand] === true
    );
  }
}

export class ProviderError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'ProviderError';
  }
}
