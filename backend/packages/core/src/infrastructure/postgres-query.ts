import { createHash } from 'node:crypto';
import type { QueryConfig } from 'pg';

export function postgresQuery(text: string, values?: unknown[]): QueryConfig {
  // Only fixed artifact authorization queries use connection-local plans.
  // Values stay bound on every execution; cached plans never cache permission results.
  if (
    /^WITH authorized AS MATERIALIZED \(SELECT a\.\* FROM signing_artifacts a WHERE a\.(?:id=\$1 AND a\.owner_id=\$2|object_key=\$1)\)/.test(
      text,
    )
  ) {
    return {
      name: 'isign_artifact_' + createHash('sha256').update(text).digest('hex').slice(0, 32),
      text,
      values,
    };
  }
  return { text, values };
}
