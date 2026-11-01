import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { cp, lstat, mkdir, mkdtemp, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
const { values } = parseArgs({ options: { app: { type: 'string' }, out: { type: 'string' } } });
if (process.platform !== 'darwin' || !values.app || !values.out)
  throw Error(
    'Usage on macOS: node backend/scripts/package-client.mjs --app /path/ISignClient.app --out /path/ISignClient.ipa',
  );
const app = path.resolve(values.app),
  output = path.resolve(values.out);
if (!(await lstat(app)).isDirectory() || !output.endsWith('.ipa'))
  throw Error('CLIENT_PACKAGE_PATH_INVALID');
const info = JSON.parse(
  execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path.join(app, 'Info.plist')], {
    encoding: 'utf8',
  }),
);
if (
  info.CFBundleIdentifier !== 'dev.h33h.feather.isign' ||
  info.CFBundlePackageType !== 'APPL' ||
  info.CFBundleDisplayName !== 'iSign Client' ||
  !/^\d+(?:\.\d+){0,2}$/.test(info.CFBundleShortVersionString ?? '')
)
  throw Error('CLIENT_RELEASE_BUILD_REQUIRED');
let serviceOrigin;
try {
  const value = info.ISignServiceOrigin;
  if (typeof value !== 'string' || !value || value !== value.trim()) throw Error();
  const url = new URL(value);
  if (
    url.protocol !== 'https:' ||
    !url.hostname ||
    url.hostname.endsWith('.invalid') ||
    url.username ||
    url.password ||
    value.includes('?') ||
    value.includes('#') ||
    (url.pathname !== '/' && url.pathname !== '')
  )
    throw Error();
  serviceOrigin = value;
} catch {
  throw Error('CLIENT_SERVICE_ORIGIN_REQUIRED: embed ISIGN_SERVICE_ORIGIN at build time');
}
const scratch = await mkdtemp(path.join(tmpdir(), 'isign-client-package-'));
try {
  const payload = path.join(scratch, 'Payload');
  await mkdir(payload);
  await cp(app, path.join(payload, 'ISignClient.app'), {
    recursive: true,
    preserveTimestamps: true,
    verbatimSymlinks: true,
  });
  const archive = path.join(scratch, 'ISignClient.ipa');
  execFileSync('/usr/bin/ditto', ['-c', '-k', '--sequesterRsrc', '--keepParent', payload, archive]);
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(archive)) digest.update(chunk);
  const metadata = {
    file: 'ISignClient.ipa',
    name: 'iSign Client',
    bundleId: info.CFBundleIdentifier,
    version: info.CFBundleShortVersionString,
    serviceOrigin,
    sha256: digest.digest('hex'),
    size: (await stat(archive)).size,
  };
  await mkdir(path.dirname(output), { recursive: true });
  // Copy then rename on the destination filesystem; /tmp and workspace may be different volumes.
  const staged = output + '.tmp-' + process.pid;
  try {
    await cp(archive, staged);
    await rename(staged, output);
  } finally {
    await rm(staged, { force: true });
  }
  await writeFile(output + '.json', JSON.stringify(metadata, null, 2) + '\n');
  process.stdout.write(JSON.stringify(metadata, null, 2) + '\n');
} finally {
  await rm(scratch, { recursive: true, force: true });
}
