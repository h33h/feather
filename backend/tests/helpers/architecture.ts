import { readdirSync, readFileSync } from 'node:fs';
import { builtinModules } from 'node:module';
import path from 'node:path';
import ts from 'typescript';

export type ArchitectureEdge = {
  from: string;
  specifier: string;
  to?: string;
  typeOnly: boolean;
  line: number;
};
export type ArchitectureGraph = {
  root: string;
  sources: Map<string, ts.SourceFile>;
  files: string[];
  edges: ArchitectureEdge[];
};
export type ArchitectureViolation = {
  rule: string;
  from: string;
  detail: string;
  chain?: string[];
};

const corePrefix = 'backend/packages/core/src/';
const webPrefix = 'web/src/';
const serverPrefix = 'backend/server/';
const contractsPrefix = 'backend/packages/contracts/src/';
const coreFeatures = new Set(['auth', 'apple', 'devices', 'signing', 'catalog', 'library']);
const builtins = new Set(builtinModules.flatMap((name) => [name, 'node:' + name]));
const slash = (filename: string) => filename.split(path.sep).join('/');
const localCssUrl = (filename: string, specifier: string) =>
  filename.endsWith('.css') && !/^(?:[a-z][a-z\d+.-]*:|\/|#)/i.test(specifier);

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const filename = path.join(directory, entry.name);
      if (entry.isDirectory())
        return ['node_modules', '.next', '.git', 'tests', '.superpowers'].includes(entry.name)
          ? []
          : sourceFiles(filename);
      return /\.(?:[cm]?ts|tsx|css)$/.test(filename) ? [filename] : [];
    })
    .sort();
}

/** Collect local dependencies without executing application code or loading dependencies. */
export function collectArchitectureGraph(root: string, roots: string[] = ['.']): ArchitectureGraph {
  root = path.resolve(root);
  const files = [
    ...new Set(roots.flatMap((directory) => sourceFiles(path.resolve(root, directory)))),
  ].sort();
  const known = new Set(files);
  const sources = new Map<string, ts.SourceFile>();
  const edges: ArchitectureEdge[] = [];
  function resolve(from: string, specifier: string): string | undefined {
    const target = localCssUrl(from, specifier)
      ? path.resolve(path.dirname(from), specifier.replace(/[?#].*$/, ''))
      : specifier.startsWith('.')
        ? path.resolve(path.dirname(from), specifier)
        : specifier.startsWith('@core/')
          ? path.join(root, corePrefix, specifier.slice(6))
          : undefined;
    if (!target) return;
    const base = target.replace(/\.(?:mjs|cjs|js|jsx)$/, '');
    return [
      target,
      base + '.ts',
      base + '.tsx',
      base + '.mts',
      base + '.cts',
      path.join(target, 'index.ts'),
      path.join(target, 'index.tsx'),
    ].find((candidate) => known.has(candidate));
  }
  for (const filename of files) {
    const content = readFileSync(filename, 'utf8');
    const add = (specifier: string, typeOnly: boolean, position: number) => {
      edges.push({
        from: filename,
        specifier,
        to: resolve(filename, specifier),
        typeOnly,
        line: content.slice(0, position).split('\n').length,
      });
    };
    if (filename.endsWith('.css')) {
      // CSS imports participate in ownership rules just like TS side-effect imports.
      for (const match of content
        .replace(/\/\*[\s\S]*?\*\//g, (comment) => comment.replace(/[^\n]/g, ' '))
        .matchAll(
          /@import\s+(?:url\(\s*(?:"([^"]+)"|'([^']+)'|([^'")\s]+))\s*\)|"([^"]+)"|'([^']+)')/gi,
        ))
        add(match[1] ?? match[2] ?? match[3] ?? match[4] ?? match[5], false, match.index);
      continue;
    }
    const tree = ts.createSourceFile(filename, content, ts.ScriptTarget.Latest, true);
    sources.set(filename, tree);
    function visit(node: ts.Node) {
      if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier)) {
        const clause = node.importClause;
        const bindings = clause?.namedBindings;
        const namedTypesOnly =
          !clause?.name &&
          bindings &&
          ts.isNamedImports(bindings) &&
          bindings.elements.length > 0 &&
          bindings.elements.every((element) => element.isTypeOnly);
        add(
          node.moduleSpecifier.text,
          Boolean(clause?.isTypeOnly || namedTypesOnly),
          node.getStart(tree),
        );
      } else if (
        ts.isExportDeclaration(node) &&
        node.moduleSpecifier &&
        ts.isStringLiteralLike(node.moduleSpecifier)
      ) {
        const namedTypesOnly =
          node.exportClause &&
          ts.isNamedExports(node.exportClause) &&
          node.exportClause.elements.length > 0 &&
          node.exportClause.elements.every((element) => element.isTypeOnly);
        add(
          node.moduleSpecifier.text,
          Boolean(node.isTypeOnly || namedTypesOnly),
          node.getStart(tree),
        );
      } else if (
        ts.isImportEqualsDeclaration(node) &&
        ts.isExternalModuleReference(node.moduleReference) &&
        node.moduleReference.expression &&
        ts.isStringLiteralLike(node.moduleReference.expression)
      ) {
        add(node.moduleReference.expression.text, node.isTypeOnly, node.getStart(tree));
      } else if (
        ts.isImportTypeNode(node) &&
        ts.isLiteralTypeNode(node.argument) &&
        ts.isStringLiteralLike(node.argument.literal)
      ) {
        add(node.argument.literal.text, true, node.getStart(tree));
      } else if (
        ts.isCallExpression(node) &&
        (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
          (ts.isIdentifier(node.expression) && node.expression.text === 'require')) &&
        node.arguments[0] &&
        ts.isStringLiteralLike(node.arguments[0])
      ) {
        add(node.arguments[0].text, false, node.getStart(tree));
      }
      ts.forEachChild(node, visit);
    }
    visit(tree);
  }
  return { root, sources, files, edges };
}

function backendModule(specifier: string): boolean {
  return (
    builtins.has(specifier) ||
    specifier.startsWith('node:') ||
    /^(?:pg|server-only|@simplewebauthn\/server|next\/server)(?:\/|$)/.test(specifier)
  );
}

export function findArchitectureViolations(graph: ArchitectureGraph): ArchitectureViolation[] {
  const violations: ArchitectureViolation[] = [];
  const relative = (filename: string) => slash(path.relative(graph.root, filename));
  const coreLayer = (filename: string) =>
    relative(filename).startsWith(corePrefix)
      ? relative(filename).slice(corePrefix.length).split('/')[0]
      : undefined;
  const outgoing = new Map<string, ArchitectureEdge[]>();
  const add = (rule: string, from: string, detail: string, chain?: string[]) =>
    violations.push({ rule, from, detail, ...(chain ? { chain } : {}) });
  for (const edge of graph.edges) {
    const list = outgoing.get(edge.from) ?? [];
    list.push(edge);
    outgoing.set(edge.from, list);
    const from = relative(edge.from);
    const to = edge.to ? relative(edge.to) : undefined;
    const owner = coreLayer(edge.from);
    const target = edge.to ? coreLayer(edge.to) : undefined;
    const detail = `${from}:${edge.line} → ${to ?? edge.specifier}`;
    if (
      !edge.to &&
      (edge.specifier.startsWith('.') ||
        edge.specifier.startsWith('@core/') ||
        localCssUrl(edge.from, edge.specifier))
    )
      add('unresolved-import', edge.from, detail);
    if (
      owner &&
      coreFeatures.has(owner) &&
      ['application', 'composition', 'infrastructure'].includes(target ?? '')
    )
      add('core-feature-layer', edge.from, detail);
    if (owner === 'application' && ['composition', 'infrastructure'].includes(target ?? ''))
      add('application-concrete', edge.from, detail);
    if (owner === 'infrastructure' && ['application', 'composition'].includes(target ?? ''))
      add('infrastructure-upper-layer', edge.from, detail);
    if (
      (owner === 'shared' || owner === 'contracts') &&
      target &&
      !['shared', 'contracts'].includes(target)
    )
      add('neutral-layer', edge.from, detail);
    if (
      from.startsWith(contractsPrefix) &&
      (target || to?.startsWith(webPrefix) || backendModule(edge.specifier))
    )
      add('neutral-layer', edge.from, detail);
    if (from.startsWith(webPrefix + 'shared/') && to?.startsWith(webPrefix + 'features/'))
      add('web-shared-feature', edge.from, detail);
    if (
      /^web\/src\/features\/(?:admin|auth)\//.test(from) &&
      to?.startsWith(webPrefix + 'features/store/')
    )
      add('independent-web-feature', edge.from, detail);
    if (
      from.startsWith(serverPrefix + 'http/') &&
      (['infrastructure', 'composition'].includes(target ?? '') ||
        (target === 'shared' && /\/(?:database|postgres)(?:\.|\/)/.test(to ?? '')))
    )
      add('http-persistence', edge.from, detail);
  }

  // Include type edges here: a browser/schema boundary must remain independent even when erased.
  for (const filename of graph.files) {
    const name = relative(filename);
    const tree = graph.sources.get(filename);
    const clientDirective = tree?.statements.some(
      (node) =>
        ts.isExpressionStatement(node) &&
        ts.isStringLiteral(node.expression) &&
        node.expression.text === 'use client',
    );
    const browser =
      name.startsWith(webPrefix + 'features/') ||
      name.startsWith(webPrefix + 'shared/') ||
      clientDirective;
    const core = name.startsWith(corePrefix);
    if (!browser && !core) continue;
    const seen = new Set([filename]);
    const queue: { filename: string; chain: string[] }[] = [{ filename, chain: [filename] }];
    for (let index = 0; index < queue.length; index++) {
      const current = queue[index];
      for (const edge of outgoing.get(current.filename) ?? []) {
        const target = edge.to ? relative(edge.to) : undefined;
        const chain = current.chain.concat(edge.to ?? edge.specifier);
        if (
          browser &&
          (backendModule(edge.specifier) ||
            target?.startsWith(serverPrefix) ||
            (target?.startsWith('backend/packages/') && !target.startsWith(contractsPrefix)))
        ) {
          add(
            'browser-server',
            filename,
            chain.map((item) => (path.isAbsolute(item) ? relative(item) : item)).join(' → '),
            chain,
          );
          continue;
        }
        if (
          core &&
          (target?.startsWith(webPrefix) ||
            /^(?:react|react-dom|next)(?:\/|$)/.test(edge.specifier))
        ) {
          add(
            'core-web',
            filename,
            chain.map((item) => (path.isAbsolute(item) ? relative(item) : item)).join(' → '),
            chain,
          );
          continue;
        }
        if (edge.to && !seen.has(edge.to)) {
          seen.add(edge.to);
          queue.push({ filename: edge.to, chain });
        }
      }
    }
  }

  // Only core runtime cycles are forbidden; feature-local type cycles are deliberately legal.
  const visited = new Set<string>();
  const active: string[] = [];
  function visit(filename: string) {
    const cycleStart = active.indexOf(filename);
    if (cycleStart !== -1) {
      const chain = active.slice(cycleStart).concat(filename);
      add('runtime-cycle', filename, chain.map(relative).join(' → '), chain);
      return;
    }
    if (visited.has(filename)) return;
    active.push(filename);
    for (const edge of outgoing.get(filename) ?? [])
      if (!edge.typeOnly && edge.to && relative(edge.to).startsWith(corePrefix)) visit(edge.to);
    active.pop();
    visited.add(filename);
  }
  for (const filename of graph.files)
    if (relative(filename).startsWith(corePrefix)) visit(filename);

  const httpFiles = [...graph.sources.keys()].filter((filename) =>
    relative(filename).startsWith(serverPrefix + 'http/'),
  );
  if (httpFiles.length) {
    const program = createArchitectureProgram(graph);
    for (const filename of httpFiles) {
      const tree = program.getSourceFile(filename);
      if (tree) inspectHttp(filename, tree, graph, program, add);
    }
    inspectHttpContexts(graph, program, add);
  }
  return violations;
}

const persistenceMembers = new Set(['db', 'database', 'query', 'transaction', 'pool']);
const transportConstructors = new Set([
  'URL',
  'URLSearchParams',
  'Request',
  'Response',
  'Headers',
  'FormData',
  'Blob',
  'File',
  'ReadableStream',
  'WritableStream',
  'TransformStream',
  'TextEncoder',
  'TextDecoder',
  'AbortController',
  'Date',
  'Map',
  'Set',
  'WeakMap',
  'WeakSet',
  'RegExp',
  'Error',
  'TypeError',
  'RangeError',
  'Promise',
  'ArrayBuffer',
  'DataView',
  'Uint8Array',
  'Uint16Array',
  'Uint32Array',
  'Int8Array',
  'Int16Array',
  'Int32Array',
  'Float32Array',
  'Float64Array',
]);

function inspectHttp(
  filename: string,
  tree: ts.SourceFile,
  graph: ArchitectureGraph,
  program: ts.Program,
  add: (rule: string, from: string, detail: string) => void,
) {
  const checker = program.getTypeChecker();
  const imported = new Map<string, { module: string }>();
  for (const statement of tree.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier))
      continue;
    const importModule = statement.moduleSpecifier.text;
    const clause = statement.importClause;
    if (clause?.name) imported.set(clause.name.text, { module: importModule });
    const bindings = clause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings))
      for (const binding of bindings.elements)
        imported.set(binding.name.text, {
          module: importModule,
        });
    else if (bindings && ts.isNamespaceImport(bindings))
      imported.set(bindings.name.text, { module: importModule });
  }
  function derivesFromNativeError(
    symbol: ts.Symbol | undefined,
    seen = new Set<ts.Symbol>(),
  ): boolean {
    if (!symbol || seen.has(symbol)) return false;
    if (symbol.flags & ts.SymbolFlags.Alias) symbol = checker.getAliasedSymbol(symbol);
    seen.add(symbol);
    if (
      symbol.name === 'Error' &&
      symbol.declarations?.some((declaration) =>
        program.isSourceFileDefaultLibrary(declaration.getSourceFile()),
      )
    )
      return true;
    return Boolean(
      symbol.declarations?.some(
        (declaration) =>
          (ts.isClassDeclaration(declaration) || ts.isClassExpression(declaration)) &&
          declaration.heritageClauses?.some(
            (heritage) =>
              heritage.token === ts.SyntaxKind.ExtendsKeyword &&
              heritage.types.some((base) =>
                derivesFromNativeError(checker.getSymbolAtLocation(base.expression), seen),
              ),
          ),
      ),
    );
  }
  const memberName = (node: ts.Node | undefined): string | undefined =>
    node && (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) ? node.text : undefined;
  function report(rule: string, node: ts.Node) {
    const line = tree.getLineAndCharacterOfPosition(node.getStart(tree)).line + 1;
    add(
      rule,
      filename,
      `${slash(path.relative(graph.root, filename))}:${line}: ${node.getText(tree).slice(0, 140)}`,
    );
  }
  function visit(node: ts.Node) {
    let property: string | undefined;
    if (ts.isPropertyAccessExpression(node)) property = node.name.text;
    else if (ts.isElementAccessExpression(node)) property = memberName(node.argumentExpression);
    else if (ts.isBindingElement(node)) property = memberName(node.propertyName ?? node.name);
    else if (ts.isPropertySignature(node) || ts.isMethodSignature(node))
      property = memberName(node.name);
    if (property && persistenceMembers.has(property)) report('http-persistence', node);
    if (
      ts.isTypeReferenceNode(node) &&
      /^(?:Database|QueryDatabase|Postgres|Pool)$/.test(node.typeName.getText(tree))
    )
      report('http-persistence', node);
    if (
      ts.isStringLiteralLike(node) &&
      /^(?:\s|--[^\n]*\n|\/\*[\s\S]*?\*\/)*(?:select\s.+\sfrom\s|insert\s+into\s|update\s+\S+\s+set\s|delete\s+from\s|create\s+table\s|alter\s+table\s)/i.test(
        node.text,
      )
    )
      report('http-persistence', node);
    if (ts.isNewExpression(node)) {
      const name = ts.isIdentifier(node.expression)
        ? node.expression.text
        : node.expression.getText(tree).split('.')[0];
      const origin = imported.get(name);
      let constructor = checker.getSymbolAtLocation(node.expression);
      if (constructor?.flags && constructor.flags & ts.SymbolFlags.Alias)
        constructor = checker.getAliasedSymbol(constructor);
      const declarations = constructor?.declarations;
      const neutralError =
        declarations?.length &&
        declarations.every(
          (declaration) =>
            slash(path.relative(graph.root, declaration.getSourceFile().fileName)) ===
            corePrefix + 'shared/errors.ts',
        );
      const localHttpError =
        declarations?.length &&
        declarations.every((declaration) =>
          slash(path.relative(graph.root, declaration.getSourceFile().fileName)).startsWith(
            serverPrefix + 'http/',
          ),
        ) &&
        derivesFromNativeError(constructor);
      const safeImport =
        neutralError ||
        localHttpError ||
        (origin && /^(?:next\/server|zod|node:stream)(?:\/|$)/.test(origin.module));
      if (!safeImport && (origin || !transportConstructors.has(name)))
        report('http-construction', node);
    }
    ts.forEachChild(node, visit);
  }
  visit(tree);
}

/** Inspect the exposed type, so aliases and ReturnType cannot hide raw database capabilities. */
function inspectHttpContexts(
  graph: ArchitectureGraph,
  program: ts.Program,
  add: (rule: string, from: string, detail: string) => void,
) {
  const contextFiles = [...graph.sources.keys()].filter((filename) =>
    /backend\/server\/http\/(?:context|application)\.ts$/.test(slash(filename)),
  );
  if (!contextFiles.length) return;
  const checker = program.getTypeChecker();
  for (const filename of contextFiles) {
    const source = program.getSourceFile(filename);
    if (!source) continue;
    const moduleSymbol = checker.getSymbolAtLocation(source);
    if (!moduleSymbol) continue;
    for (const exported of checker.getExportsOfModule(moduleSymbol)) {
      const resolved =
        exported.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(exported) : exported;
      if (
        !(
          resolved.flags &
          (ts.SymbolFlags.TypeAlias | ts.SymbolFlags.Interface | ts.SymbolFlags.Class)
        )
      )
        continue;
      const seen = new Set<ts.Type>();
      function inspect(type: ts.Type, chain: string[]) {
        if (seen.has(type)) return;
        seen.add(type);
        if (type.isUnionOrIntersection()) {
          for (const member of type.types) inspect(member, chain);
          return;
        }
        for (const property of checker.getPropertiesOfType(type)) {
          const declaration = property.valueDeclaration ?? property.declarations?.[0];
          // Request/stream/framework internals are transport capabilities, not application context.
          if (!declaration || !graph.sources.has(declaration.getSourceFile().fileName)) continue;
          const next = chain.concat(property.name);
          if (persistenceMembers.has(property.name)) {
            add(
              'http-context-persistence',
              filename,
              `${slash(path.relative(graph.root, filename))}: ${next.join('.')} exposes persistence`,
            );
            continue;
          }
          const propertyType = checker.getTypeOfSymbolAtLocation(property, declaration);
          if (!propertyType.getCallSignatures().length) inspect(propertyType, next);
        }
      }
      inspect(checker.getDeclaredTypeOfSymbol(resolved), [exported.name]);
    }
  }
}

function createArchitectureProgram(graph: ArchitectureGraph): ts.Program {
  return ts.createProgram([...graph.sources.keys()], {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    jsx: ts.JsxEmit.ReactJSX,
    strict: true,
    skipLibCheck: true,
    noEmit: true,
    paths: { '@core/*': [path.join(graph.root, corePrefix, '*')] },
  });
}
