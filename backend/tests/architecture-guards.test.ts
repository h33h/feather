import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { collectArchitectureGraph, findArchitectureViolations } from './helpers/architecture';

const temporaryRoots: string[] = [];
afterEach(() =>
  temporaryRoots.splice(0).forEach((root) => rmSync(root, { recursive: true, force: true })),
);
function fixture(files: Record<string, string>) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'isign-architecture-'));
  temporaryRoots.push(root);
  for (const [filename, content] of Object.entries(files)) {
    const target = path.join(root, filename);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return collectArchitectureGraph(root);
}
const core = 'backend/packages/core/src/';
const web = 'web/src/';
const server = 'backend/server/';
const codes = (graph: ReturnType<typeof fixture>) =>
  findArchitectureViolations(graph).map((v) => v.rule);

describe('architecture graph scanner', () => {
  it('collects TSX, relative index imports, .js targets and the @core alias', () => {
    const graph = fixture({
      [web + 'features/auth/view.tsx']:
        `import type { Secret } from '@core/auth/index.js'; export const View = () => <div />;`,
      [core + 'auth/index.ts']: `export type { Secret } from './secret';`,
      [core + 'auth/secret/index.ts']: 'export type Secret = string;',
    });
    expect(
      graph.edges.map((edge) => [
        edge.specifier,
        edge.typeOnly,
        edge.to && path.relative(graph.root, edge.to),
      ]),
    ).toEqual([
      ['./secret', true, core + 'auth/secret/index.ts'],
      ['@core/auth/index.js', true, core + 'auth/index.ts'],
    ]);
    expect(codes(graph)).toContain('browser-server');
  });
  it.each([
    `import type { Hidden } from '@core/composition/root';`,
    `import { type Hidden } from '@core/composition/root';`,
    `export type { Hidden } from '@core/composition/root';`,
    `export { type Hidden } from '@core/composition/root';`,
    `export type * from '@core/composition/root';`,
    `type Hidden = import('@core/composition/root').Hidden;`,
    `type Hidden = typeof import('@core/composition/root');`,
    `import type Hidden = require('@core/composition/root');`,
  ])('enforces layer direction for type-only syntax: %s', (source) => {
    const graph = fixture({
      [core + 'auth/consumer.ts']: source,
      [core + 'composition/root.ts']: 'export type Hidden = string;',
    });
    expect(codes(graph)).toContain('core-feature-layer');
    expect(graph.edges).toHaveLength(1);
    expect(graph.edges[0].typeOnly).toBe(true);
  });
  it.each([
    `export async function load() { return import('@core/infrastructure/adapter'); }`,
    `export function load() { return require('@core/infrastructure/adapter'); }`,
    `export { adapter } from '@core/infrastructure/adapter';`,
    `import { type Hidden, adapter } from '@core/infrastructure/adapter';`,
  ])('finds runtime edges including function-local loading: %s', (source) => {
    const graph = fixture({
      [core + 'application/scenario.ts']: source,
      [core + 'infrastructure/adapter.ts']:
        'export const adapter = 1; export type Hidden = string;',
    });
    expect(codes(graph)).toContain('application-concrete');
    expect(graph.edges[0].typeOnly).toBe(false);
  });
  it('follows a transitive client dependency through a neutral-looking barrel', () => {
    const graph = fixture({
      [web + 'app/widget.tsx']:
        `'use client'; import { value } from '../../../backend/packages/contracts/src'; export const Widget = () => <div>{value}</div>;`,
      'backend/packages/contracts/src/index.ts': `export { value } from '../../../../bridge';`,
      'bridge.ts': `export { value } from './backend/server/private';`,
      [server + 'private.ts']: 'export const value = 1;',
    });
    const violation = findArchitectureViolations(graph).find(
      (v) => v.rule === 'browser-server' && v.from.endsWith('widget.tsx'),
    );
    expect(violation?.chain?.map((filename) => path.relative(graph.root, filename))).toEqual([
      web + 'app/widget.tsx',
      'backend/packages/contracts/src/index.ts',
      'bridge.ts',
      server + 'private.ts',
    ]);
  });
  it.each(['node:fs', 'fs/promises', 'pg', 'next/server', 'server-only'])(
    'rejects browser backend dependency %s',
    (specifier) => {
      expect(
        codes(
          fixture({
            [web + 'shared/api/leak.ts']: `import type * as Backend from '${specifier}';`,
          }),
        ),
      ).toContain('browser-server');
    },
  );
  it('rejects feature coupling through CSS imports and CSS @import chains', () => {
    const graph = fixture({
      [web + 'features/admin/users.tsx']: `import './users.css';`,
      [web + 'features/admin/users.css']: `@import '../store/store.css';`,
      [web + 'features/store/store.css']: '.store {}',
      [web + 'features/auth/view.tsx']: `import '../store/store.css';`,
      [web + 'shared/ui/panel.tsx']: `import '../../features/store/store.css';`,
    });
    expect(codes(graph).filter((rule) => rule === 'independent-web-feature')).toHaveLength(2);
    expect(codes(graph)).toContain('web-shared-feature');
  });
  it('rejects neutral contracts importing concrete publishers and core importing web transitively', () => {
    const graph = fixture({
      [core + 'shared/contracts.ts']: `export type { Publisher } from '../signing/publisher';`,
      [core + 'signing/publisher.ts']: 'export type Publisher = string;',
      [core + 'auth/session.ts']: `import type { Session } from '../../../contracts/src';`,
      'backend/packages/contracts/src/index.ts': `export type { Session } from '../../../../web/src/shared/session';`,
      [web + 'shared/session.ts']: 'export type Session = string;',
    });
    expect(codes(graph)).toContain('neutral-layer');
    expect(codes(graph)).toContain('core-web');
  });
  it('rejects infrastructure importing application or composition and features importing infrastructure', () => {
    const graph = fixture({
      [core + 'infrastructure/adapter.ts']:
        `import type { App } from '../application/use-case'; import '../composition/root';`,
      [core + 'application/use-case.ts']: 'export type App = string;',
      [core + 'composition/root.ts']: 'export {};',
      [core + 'devices/use-case.ts']: `import '../infrastructure/adapter';`,
    });
    expect(codes(graph).filter((rule) => rule === 'infrastructure-upper-layer')).toHaveLength(2);
    expect(codes(graph)).toContain('core-feature-layer');
  });
  it('reports runtime cycles while allowing intra-feature type-only cycles', () => {
    const typeGraph = fixture({
      [core + 'auth/a.ts']: `import { type B } from './b'; export type A = B;`,
      [core + 'auth/b.ts']: `export type { A as B } from './a';`,
    });
    expect(codes(typeGraph)).not.toContain('runtime-cycle');
    const runtimeGraph = fixture({
      [core + 'auth/a.ts']: `export { b } from './b'; export const a = 1;`,
      [core + 'auth/b.ts']: `export function b() { return require('./a'); }`,
    });
    expect(codes(runtimeGraph)).toContain('runtime-cycle');
  });
  it('reports unresolved local and alias imports instead of silently losing edges', () => {
    const graph = fixture({ [core + 'auth/a.ts']: `import './missing'; import '@core/missing';` });
    expect(codes(graph).filter((rule) => rule === 'unresolved-import')).toHaveLength(2);
  });
  it.each([
    'await app.db.query("select * from users")',
    'await app["database"]["transaction"](() => {})',
    'const { db: persistence } = app;',
    'const { query } = app; await query("select 1")',
    'const sql = `delete from users where id = $1`;',
    'export type Context = { db: Database };',
    'export type Context = { persistence: QueryDatabase };',
    `import { Service as Constructor } from '@core/auth/service'; new Constructor();`,
    'class CustomBusinessService {} new CustomBusinessService();',
  ])('rejects persistence or business construction in HTTP: %s', (source) => {
    const graph = fixture({
      [server + 'http/handler.ts']: source,
      [core + 'auth/service.ts']: 'export class Service {}',
    });
    expect(
      codes(graph).some((rule) => rule === 'http-persistence' || rule === 'http-construction'),
    ).toBe(true);
  });
  it('rejects HTTP contexts exposing persistence indirectly through a runtime return type', () => {
    const graph = fixture({
      [server + 'composition.ts']:
        `export function runtime() { return { persistence: { query(sql: string) { return sql; } } }; }`,
      [server + 'http/context.ts']:
        `import type { runtime } from '../composition'; export type Context = { app: ReturnType<typeof runtime> };`,
    });
    expect(codes(graph)).toContain('http-context-persistence');
  });

  it('allows HTTP contexts projecting public operations away from runtime persistence', () => {
    const graph = fixture({
      [server + 'composition.ts']:
        `export function runtime() { return { db: { query(sql: string) { return sql; } }, session() { return 'session'; } }; }`,
      [server + 'http/context.ts']:
        `import type { runtime } from '../composition'; type Runtime = ReturnType<typeof runtime>; export type Context = { app: Pick<Runtime, 'session'> };`,
    });
    expect(findArchitectureViolations(graph)).toEqual([]);
  });

  it('allows local HTTP exceptions derived from the native Error type', () => {
    const graph = fixture({
      [server + 'http/handler.ts']:
        `class PresentationError extends Error {} new PresentationError('invalid response');`,
    });
    expect(findArchitectureViolations(graph)).toEqual([]);
  });

  it('rejects a local business constructor masquerading behind a shadowed Error class', () => {
    const graph = fixture({
      [server + 'http/handler.ts']:
        `export {}; class Error {} class PresentationError extends Error {} new PresentationError();`,
    });
    expect(codes(graph)).toContain('http-construction');
  });

  it('rejects a business constructor after an unrelated neutral error star export', () => {
    const graph = fixture({
      [core + 'shared/errors.ts']: 'export class Failure extends Error {}',
      [core + 'auth/service.ts']: 'export class Service {}',
      [core + 'auth/index.ts']: `export * from '../shared/errors'; export * from './service';`,
      [server + 'http/handler.ts']: `import { Service } from '@core/auth/index'; new Service();`,
    });
    expect(codes(graph)).toContain('http-construction');
  });

  it('allows the actual neutral error after an unrelated business service star export', () => {
    const graph = fixture({
      [core + 'shared/errors.ts']: 'export class Failure extends Error {}',
      [core + 'auth/service.ts']: 'export class Service {}',
      [core + 'auth/index.ts']: `export * from './service'; export * from '../shared/errors';`,
      [server + 'http/handler.ts']:
        `import { Failure as HttpFailure } from '@core/auth/index'; new HttpFailure();`,
    });
    expect(findArchitectureViolations(graph)).toEqual([]);
  });

  it.each([
    `export type { Context as PublicContext } from '../exposed';`,
    `export type * from '../exposed';`,
  ])('rejects persistence exposed through HTTP type reexports: %s', (reexport) => {
    const graph = fixture({
      [server + 'composition.ts']:
        `export function runtime() { return { persistence: { query(sql: string) { return sql; } } }; }`,
      [server + 'exposed.ts']:
        `import type { runtime } from './composition'; export type Context = { app: ReturnType<typeof runtime> };`,
      [server + 'http/context.ts']: reexport,
    });
    expect(codes(graph)).toContain('http-context-persistence');
  });

  it.each([
    `export type { Context as PublicContext } from '../exposed';`,
    `export type * from '../exposed';`,
  ])('allows reexported HTTP context projections: %s', (reexport) => {
    const graph = fixture({
      [server + 'composition.ts']:
        `export function runtime() { return { db: { query(sql: string) { return sql; } }, session() { return 'session'; } }; }`,
      [server + 'exposed.ts']:
        `import type { runtime } from './composition'; export type Context = { app: Pick<ReturnType<typeof runtime>, 'session'> };`,
      [server + 'http/context.ts']: reexport,
    });
    expect(findArchitectureViolations(graph)).toEqual([]);
  });

  it('rejects unquoted local CSS import URLs across features including bare relative URLs', () => {
    const graph = fixture({
      [web + 'features/admin/users.tsx']: `import './users.css';`,
      [web + 'features/admin/users.css']:
        `@import url(../store/store.css); @import url(theme.css);`,
      [web + 'features/admin/theme.css']: `@import url( ../store/store.css ) screen;`,
      [web + 'features/store/store.css']: '.store {}',
    });
    expect(
      graph.edges
        .filter((edge) => edge.from.endsWith('users.css'))
        .map((edge) => edge.to && path.relative(graph.root, edge.to)),
    ).toEqual([web + 'features/store/store.css', web + 'features/admin/theme.css']);
    expect(codes(graph).filter((rule) => rule === 'independent-web-feature')).toHaveLength(2);
  });

  it('allows unquoted CSS imports to neutral styles and external URLs', () => {
    const graph = fixture({
      [web + 'features/admin/users.tsx']: `import './users.css';`,
      [web + 'features/admin/users.css']:
        `@import url(../../shared/ui/base.css); @import url(https://example.com/theme.css); @import url(//example.com/print.css) print;`,
      [web + 'shared/ui/base.css']: ':root {}',
    });
    expect(
      graph.edges.filter((edge) => edge.from.endsWith('users.css')).map((edge) => edge.specifier),
    ).toEqual([
      '../../shared/ui/base.css',
      'https://example.com/theme.css',
      '//example.com/print.css',
    ]);
    expect(findArchitectureViolations(graph)).toEqual([]);
  });

  it('allows neutral protocols, use-case ports, composition, transport classes and store-to-auth UI', () => {
    const graph = fixture({
      [core + 'shared/protocol.ts']: 'export type Protocol = string;',
      [core + 'auth/port.ts']:
        `import type { Protocol } from '../shared/protocol'; export type Auth = Protocol;`,
      [core + 'application/scenario.ts']:
        `import type { Auth } from '../auth/port'; export type Scenario = Auth;`,
      [core + 'infrastructure/adapter.ts']:
        `import type { Auth } from '../auth/port'; export const adapter: Auth = '';`,
      [core + 'composition/root.ts']:
        `import '../application/scenario'; import '../infrastructure/adapter';`,
      [core + 'shared/errors.ts']: 'export class Failure extends Error {}',
      [core + 'shared/index.ts']: `export { Failure } from './errors';`,
      [server + 'http/handler.ts']:
        `import { Failure as HttpFailure } from '@core/shared/index'; import { NextResponse } from 'next/server'; import { z } from 'zod'; new HttpFailure(); new NextResponse(); new URL('/'); new ReadableStream(); z.object({});`,
      [web + 'features/store/screen.tsx']: `import '../auth/controls'; import '../../shared/ui';`,
      [web + 'features/auth/controls.tsx']: `import '../../shared/ui';`,
      [web + 'shared/ui/index.tsx']: 'export const View = () => <div />;',
    });
    expect(findArchitectureViolations(graph)).toEqual([]);
  });
});
