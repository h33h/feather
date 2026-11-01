import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../deploy/personal/deploy.sh', import.meta.url));
const image = `sha256:${'a'.repeat(64)}`;
const commit = 'b'.repeat(40);

function runDeploy(mode) {
  const root = mkdtempSync(path.join(tmpdir(), 'isign-deploy-'));
  const bin = path.join(root, 'bin');
  mkdirSync(bin);
  const environment = 'POSTGRES_IMAGE=postgres@sha256:existing\nWEB_IMAGE=old-web\n';
  let compose =
    'services:\n  web:\n    command: [node, --import, tsx, scripts/personal-start.ts]\n    tmpfs: ["/tmp:size=123", "/app/apps/web/.next/cache:size=456"]\n    env_file: [personal.env]\n    ports: ["127.0.0.1:3080:3000"]\n';
  if (mode === 'current-layout')
    compose = compose
      .replace('scripts/personal-start.ts', 'backend/scripts/personal-start.ts')
      .replace('/app/apps/web/.next/cache', '/app/web/.next/cache');
  writeFileSync(path.join(root, '.env'), environment);
  writeFileSync(path.join(root, 'compose.yml'), compose);
  writeFileSync(path.join(root, 'image.tar.gz'), 'fixture');
  writeFileSync(path.join(root, 'docker.log'), '');
  writeFileSync(path.join(root, 'curl.log'), '');
  writeFileSync(
    path.join(bin, 'docker'),
    `#!/bin/bash
printf '%s\\n' "$*" >> "$DEPLOY_TEST_ROOT/docker.log"
case "$*" in
  *'exec -T web node -p'*) echo isign.cloudnodex.ru ;;
  *'ps -q web'*) echo container ;;
  'image inspect '*"--format {{.Id}}") echo '${image}' ;;
  *'org.opencontainers.image.revision'*)
    if [ "$DEPLOY_TEST_MODE" = wrong-revision ]; then echo wrong; else echo "$DEPLOY_TEST_COMMIT"; fi ;;
  'inspect --format {{.Image}} container') echo old-image ;;
  'image ls --no-trunc --format {{.ID}} {{.ID}} isign-web')
    printf '%s\\n' 'old-image old-image' 'stale-image stale-image' ;;
  *'config --quiet'*) [ "$DEPLOY_TEST_MODE" != invalid-config ] ;;
  *'up --no-deps --detach --pull never --wait --wait-timeout 120 web'*)
    [ "$DEPLOY_TEST_MODE" != failed-start ] || [ "\${WEB_IMAGE:-}" = old-image ] || exit 1
    printf '%s' "\${WEB_IMAGE:-${image}}" > "$DEPLOY_TEST_ROOT/running-image" ;;
  *'stop web') touch "$DEPLOY_TEST_ROOT/stopped" ;;
  'image ls --no-trunc --format {{.Repository}}:{{.Tag}} {{.ID}} isign-web')
    if [ "$DEPLOY_TEST_MODE" != displaced-tag ]; then echo 'isign-web:old old-image'; fi
    printf '%s\\n' 'isign-web:stale stale-image' 'isign-web:${commit} ${image}' ;;
  'image inspect old-image --format {{len .RepoTags}}')
    if [ "$DEPLOY_TEST_MODE" = shared-image ]; then echo 1; else echo 0; fi ;;
  'image inspect old-image') [ ! -f "$DEPLOY_TEST_ROOT/deleted-old" ] ;;
  'ps --all --quiet --filter ancestor='*)
    running=old-image
    if [ -f "$DEPLOY_TEST_ROOT/running-image" ]; then running="$(cat "$DEPLOY_TEST_ROOT/running-image")"; fi
    if [ "\${*: -1}" = "ancestor=$running" ]; then echo container; fi ;;
  'image rm isign-web:old')
    [ "$DEPLOY_TEST_MODE" != failed-cleanup ] || exit 1
    if [ "$DEPLOY_TEST_MODE" != shared-image ]; then touch "$DEPLOY_TEST_ROOT/deleted-old"; fi ;;
  'image rm '*) [ "$DEPLOY_TEST_MODE" != failed-cleanup ] ;;
esac
`,
    { mode: 0o700 },
  );
  writeFileSync(
    path.join(bin, 'curl'),
    `#!/bin/bash
printf '%s\\n' "$*" >> "$DEPLOY_TEST_ROOT/curl.log"
[ "$DEPLOY_TEST_MODE" != failed-health ] || exit 1
if [[ "$*" == *'/api/health'* ]]; then
  [ "$DEPLOY_TEST_MODE" != uninitialized-api ] || exit 22
fi
`,
    {
      mode: 0o700,
    },
  );
  writeFileSync(path.join(bin, 'flock'), '#!/bin/bash\nexit 0\n', { mode: 0o700 });
  try {
    const result = spawnSync('bash', [script, root, path.join(root, 'image.tar.gz'), commit], {
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        DEPLOY_TEST_ROOT: root,
        DEPLOY_TEST_MODE: mode,
        DEPLOY_TEST_COMMIT: commit,
      },
      encoding: 'utf8',
    });
    return {
      ...result,
      environment: readFileSync(path.join(root, '.env'), 'utf8'),
      log: readFileSync(path.join(root, 'docker.log'), 'utf8'),
      probes: readFileSync(path.join(root, 'curl.log'), 'utf8'),
      original: environment,
      compose: readFileSync(path.join(root, 'compose.yml'), 'utf8'),
      originalCompose: compose,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('healthy deployment persists the image without dropping database settings', () => {
  const result = runDeploy('success');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.environment, `POSTGRES_IMAGE=postgres@sha256:existing\nWEB_IMAGE=${image}\n`);
});

test('deployment upgrades runtime paths while preserving operator Compose settings', () => {
  const result = runDeploy('success');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.compose,
    result.originalCompose
      .replace('scripts/personal-start.ts', 'backend/scripts/personal-start.ts')
      .replace('/app/apps/web/.next/cache', '/app/web/.next/cache'),
  );
});

test('a repeated deployment keeps the current runtime paths unchanged', () => {
  const result = runDeploy('current-layout');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.compose, result.originalCompose);
});

test('deployment probes runtime readiness with the canonical Host header', () => {
  const result = runDeploy('success');
  assert.match(result.probes, /Host: isign.cloudnodex.ru/);
  assert.match(result.probes, /http:\/\/127.0.0.1:3080\/api\/health/);
});

test('a healthy static page cannot hide an uninitialized API', () => {
  const result = runDeploy('uninitialized-api');
  assert.notEqual(result.status, 0);
  assert.equal(result.environment, result.original);
  assert.match(result.log, /stop web/);
});

test('successful deployment removes old web images and keeps the running image', () => {
  const result = runDeploy('success');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.log, /image rm isign-web:old\n/);
  assert.match(result.log, /image rm isign-web:stale\n/);
  assert.doesNotMatch(result.log, new RegExp(`image rm isign-web:${commit}`));
});

test('deployment removes pre-load web images even if loading displaces their tags', () => {
  const result = runDeploy('displaced-tag');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.log, /image rm old-image\n/);
  assert.doesNotMatch(result.log, new RegExp(`image rm ${image}`));
});

test('cleanup preserves image IDs that still have tags in another repository', () => {
  const result = runDeploy('shared-image');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.log, /image rm isign-web:old\n/);
  assert.doesNotMatch(result.log, /image rm old-image\n/);
});

for (const mode of ['failed-start', 'failed-health']) {
  test(`${mode} keeps settings and stops the failed service without starting previous code`, () => {
    const result = runDeploy(mode);
    assert.notEqual(result.status, 0);
    assert.equal(result.environment, result.original);
    assert.equal(result.compose, result.originalCompose);
    assert.doesNotMatch(result.stderr, /Restoring previous web image/);
    assert.match(result.log, /stop web/);
    assert.equal(result.log.match(/up --no-deps/g)?.length, 1);
    if (mode === 'failed-start')
      assert.match(result.log, new RegExp(`image rm isign-web:${commit}`));
    else assert.doesNotMatch(result.log, new RegExp(`image rm isign-web:${commit}`));
    assert.match(result.log, /image rm isign-web:stale\n/);
    if (mode === 'failed-health') assert.match(result.log, /image rm isign-web:old\n/);
    else assert.doesNotMatch(result.log, /image rm isign-web:old\n/);
  });
}

test('invalid Compose configuration never restarts the application', () => {
  const result = runDeploy('invalid-config');
  assert.notEqual(result.status, 0);
  assert.equal(result.environment, result.original);
  assert.equal(result.compose, result.originalCompose);
  assert.match(result.log, /load --input/);
  assert.doesNotMatch(result.log, /up --no-deps/);
});

test('cleanup failure does not turn a healthy deployment into a failed deployment', () => {
  const result = runDeploy('failed-cleanup');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.log, /image rm isign-web:old\n/);
  assert.match(result.stderr, /Could not remove unused web image/);
  assert.equal(result.environment, `POSTGRES_IMAGE=postgres@sha256:existing\nWEB_IMAGE=${image}\n`);
});

test('an image with the wrong commit label never restarts the application', () => {
  const result = runDeploy('wrong-revision');
  assert.notEqual(result.status, 0);
  assert.equal(result.environment, result.original);
  assert.match(result.log, /load --input/);
  assert.doesNotMatch(result.log, /up --no-deps/);
});
