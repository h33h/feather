import { expect, it } from 'vitest';
import { postgresQuery } from '../packages/core/src/infrastructure/postgres-query';

const ticket =
  'WITH authorized AS MATERIALIZED (SELECT a.* FROM signing_artifacts a WHERE a.id=$1 AND a.owner_id=$2) SELECT a.id FROM authorized a';
const storage =
  'WITH authorized AS MATERIALIZED (SELECT a.* FROM signing_artifacts a WHERE a.object_key=$1) SELECT a.id FROM authorized a';

it('reuses the same prepared statement across different download credentials', () => {
  const first = postgresQuery(ticket, ['artifact-1', 'owner-1']);
  const second = postgresQuery(ticket, ['artifact-2', 'owner-2']);
  expect(first.name).toMatch(/^isign_artifact_[a-f0-9]{32}$/);
  expect(second.name).toBe(first.name);
  expect(first.text).toBe(ticket);
  expect(first.values).toEqual(['artifact-1', 'owner-1']);
  expect(second.values).toEqual(['artifact-2', 'owner-2']);
});
it('never reuses a prepared name for different authorization SQL', () => {
  const base = postgresQuery(ticket, []);
  expect(postgresQuery(storage, []).name).not.toBe(base.name);
  expect(postgresQuery(ticket + ' WHERE false', []).name).not.toBe(base.name);
});
it('leaves other statements unnamed to bound the server plan cache', () => {
  expect(postgresQuery('SELECT id FROM users WHERE id=$1', ['owner'])).toEqual({
    text: 'SELECT id FROM users WHERE id=$1',
    values: ['owner'],
  });
});
