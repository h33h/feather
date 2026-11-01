import path from 'node:path';
import { expect, it } from 'vitest';
import { collectArchitectureGraph, findArchitectureViolations } from './helpers/architecture';

it('keeps browser, transport, application, domain and adapter dependencies within their layers', () => {
  const graph = collectArchitectureGraph(path.resolve('.'), [
    'backend/packages/core/src',
    'backend/packages/contracts/src',
    'web/src',
    'backend/server',
  ]);
  const violations = findArchitectureViolations(graph);
  expect(violations.map((violation) => `[${violation.rule}] ${violation.detail}`)).toEqual([]);
});
