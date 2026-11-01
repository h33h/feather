/** Error fields only: never log request bodies, grants, signing material or arbitrary objects. */
export function diagnosticError(
  error: unknown,
  env: Record<string, string | undefined> = process.env,
): Record<string, unknown> {
  const secrets = Object.entries(env)
    .filter(
      ([key, value]) =>
        /TOKEN|SECRET|PASSWORD|PRIVATE|PROOF_KEY|DATABASE_URL/.test(key) &&
        value &&
        value.length >= 4,
    )
    .map(([, value]) => value!)
    .sort((a, b) => b.length - a.length);
  const redact = (value: string) => {
    for (const secret of secrets) value = value.split(secret).join('[REDACTED]');
    return value
      .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '[REDACTED PEM]')
      .replace(/Bearer\s+[^\s,;]+/gi, 'Bearer [REDACTED]')
      .replace(/https?:\/\/[^\s<>"']+/g, (raw) => {
        try {
          const url = new URL(raw);
          return url.origin + url.pathname;
        } catch {
          return '[REDACTED URL]';
        }
      })
      .slice(0, 4000);
  };
  const seen = new Set<unknown>();
  const describe = (value: unknown, depth: number): Record<string, unknown> => {
    if (!(value instanceof Error))
      return {
        name: 'NonError',
        message: typeof value === 'string' ? redact(value) : 'Non-error thrown',
      };
    if (seen.has(value) || depth >= 4) return { name: 'TruncatedCause' };
    seen.add(value);
    const result: Record<string, unknown> = {
      name: redact(value.name),
      message: redact(value.message),
    };
    if (value.stack) result.stack = redact(value.stack);
    for (const field of ['code', 'errno', 'syscall'] as const) {
      const item = (value as unknown as Record<string, unknown>)[field];
      if (typeof item === 'string') result[field] = redact(item);
      else if (typeof item === 'number') result[field] = item;
    }
    if (value.cause !== undefined) result.cause = describe(value.cause, depth + 1);
    return result;
  };
  return describe(error, 0);
}
