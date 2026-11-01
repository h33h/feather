import { afterAll, beforeAll, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import {
  deviceCollectionCms,
  APPLE_PROFILE_SERVICE_CA_PEM,
  APPLE_PROFILE_SERVICE_CA_SHA256,
} from '../packages/core/src/infrastructure/collection-cms';
const udid = '00008030-0000000000000000',
  challenge = 'a'.repeat(43);
let directory: string, caPem: string, caSha256: string;
const openssl = (args: string[]) =>
  execFileSync('/usr/bin/openssl', args, { cwd: directory, stdio: 'pipe', timeout: 10000 });
beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'isign-cms-test-'));
  await writeFile(
    join(directory, 'ca.cnf'),
    '[req]\ndistinguished_name=dn\n[dn]\n[ca_ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n',
  );
  openssl([
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    'ca.key',
    '-out',
    'ca.pem',
    '-days',
    '1',
    '-subj',
    '/CN=Synthetic Device CA',
    '-config',
    'ca.cnf',
    '-extensions',
    'ca_ext',
  ]);
  openssl([
    'req',
    '-new',
    '-newkey',
    'rsa:2048',
    '-nodes',
    '-keyout',
    'leaf.key',
    '-out',
    'leaf.csr',
    '-subj',
    '/CN=' + udid,
  ]);
  await writeFile(
    join(directory, 'leaf.ext'),
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n',
  );
  openssl([
    'x509',
    '-req',
    '-in',
    'leaf.csr',
    '-CA',
    'ca.pem',
    '-CAkey',
    'ca.key',
    '-CAcreateserial',
    '-out',
    'leaf.pem',
    '-days',
    '1',
    '-extfile',
    'leaf.ext',
  ]);
  openssl([
    'req',
    '-new',
    '-key',
    'leaf.key',
    '-out',
    'modern.csr',
    '-subj',
    '/CN=opaque-device-certificate',
  ]);
  openssl([
    'x509',
    '-req',
    '-in',
    'modern.csr',
    '-CA',
    'ca.pem',
    '-CAkey',
    'ca.key',
    '-CAcreateserial',
    '-out',
    'modern.pem',
    '-days',
    '1',
    '-extfile',
    'leaf.ext',
  ]);
  openssl(['req', '-new', '-key', 'leaf.key', '-out', 'empty.csr', '-subj', '/']);
  openssl([
    'x509',
    '-req',
    '-in',
    'empty.csr',
    '-CA',
    'ca.pem',
    '-CAkey',
    'ca.key',
    '-CAcreateserial',
    '-out',
    'empty.pem',
    '-days',
    '1',
    '-extfile',
    'leaf.ext',
  ]);
  caPem = await readFile(join(directory, 'ca.pem'), 'utf8');
  caSha256 = createHash('sha256').update(new X509Certificate(caPem).raw).digest('hex');
});
afterAll(async () => {
  if (directory) await rm(directory, { recursive: true, force: true });
});
const xml = (extra = '', deviceUdid = udid) =>
  `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CHALLENGE</key><string>${challenge}</string><key>UDID</key><string>${deviceUdid}</string><key>PRODUCT</key><string>iPhone15,2</string>${extra}</dict></plist>`;
async function signed(payload: string, certificate = 'leaf.pem') {
  await writeFile(join(directory, 'payload.plist'), payload);
  openssl([
    'cms',
    '-sign',
    '-binary',
    '-nodetach',
    '-in',
    'payload.plist',
    '-signer',
    certificate,
    '-inkey',
    'leaf.key',
    '-outform',
    'DER',
    '-out',
    'signed.cms',
  ]);
  return readFile(join(directory, 'signed.cms'));
}
const verifier = () =>
  deviceCollectionCms({
    opensslPath: '/usr/bin/openssl',
    udidSubjectAttribute: 'CN',
    deviceCaPem: caPem,
    deviceCaSha256: caSha256,
  });
it('requires an explicit leaf UDID policy before configuring local CMS verification', () => {
  expect(() => deviceCollectionCms({} as never)).toThrow('CMS_DEVICE_POLICY_REQUIRED');
});
it('pins the official published Apple device CA bytes and rejects a changed anchor', () => {
  expect(
    createHash('sha256')
      .update(new X509Certificate(APPLE_PROFILE_SERVICE_CA_PEM).raw)
      .digest('hex'),
  ).toBe(APPLE_PROFILE_SERVICE_CA_SHA256);
  expect(() =>
    deviceCollectionCms({
      udidSubjectAttribute: 'CN',
      deviceCaPem: caPem,
      deviceCaSha256: '0'.repeat(64),
    }),
  ).toThrow('CMS_CONFIGURATION_INVALID');
});
it('verifies a real CMS signature and binds the signer subject to its device UDID', async () => {
  expect(await verifier()(await signed(xml('<key>VERSION</key><string>18.0</string>')))).toEqual({
    challenge,
    udid,
    product: 'iPhone15,2',
    version: '18.0',
    signatureVerified: true,
    issuerTrusted: true,
    deviceCertificate: true,
  });
});
it('rejects unsigned plist and a CMS signed outside the pinned Apple device hierarchy', async () => {
  await expect(verifier()(Buffer.from(xml()))).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    deviceCollectionCms({ udidSubjectAttribute: 'CN', opensslPath: '/usr/bin/openssl' })(
      await signed(xml()),
    ),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
});
it('rejects a modified CMS signature and a signed mismatched UDID', async () => {
  const body = await signed(xml());
  body[body.length - 1] ^= 1;
  await expect(verifier()(body)).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(verifier()(await signed(xml('', '00008030-1111111111111111')))).rejects.toThrow(
    'INVALID_DEVICE_CALLBACK',
  );
});
it('rejects duplicate keys and entity declarations even inside signed CMS', async () => {
  await expect(
    verifier()(await signed(xml('<key>UDID</key><string>' + udid + '</string>'))),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    verifier()(
      await signed(
        xml().replace(
          '<plist',
          '<!DOCTYPE x [<!ENTITY attack SYSTEM "file:///etc/passwd">]><plist',
        ),
      ),
    ),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
});
it('does not treat an Apple build identifier as a reported iOS version', async () => {
  expect(
    await verifier()(await signed(xml('<key>VERSION</key><string>23B85</string>'))),
  ).not.toHaveProperty('version');
});

it('discards signed extra device attributes while retaining the required enrollment identity', async () => {
  const extra =
    '<key>MAC_ADDRESS_EN0</key><string>00:00:00:00:00:00</string><key>SERIAL</key><string>synthetic-private-serial</string><key>IMEI</key><string>synthetic-private-imei</string><key>UNREQUESTED</key><string></string>';
  expect(await verifier()(await signed(xml(extra)))).toEqual({
    challenge,
    udid,
    product: 'iPhone15,2',
    signatureVerified: true,
    issuerTrusted: true,
    deviceCertificate: true,
  });
});
it.each([
  '<?xml version="1.0"?>',
  "<?xml version='1.0' encoding='UTF-8' standalone='yes'?>",
  '<?xml version="1.0" standalone="no"?>',
])('accepts the valid XML declaration %s inside verified CMS', async (declaration) => {
  const payload = xml().replace('<?xml version="1.0" encoding="UTF-8"?>', declaration);
  expect(await verifier()(await signed(payload))).toMatchObject({ challenge, udid });
});
it.each(['Apple', 'Apple Inc', 'Apple Computer'])(
  'accepts the published %s plist DOCTYPE inside verified CMS',
  async (organization) => {
    const payload = xml()
      .replace(
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        `<!DOCTYPE plist PUBLIC '-//${organization}//DTD PLIST 1.0//EN' 'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>`,
      )
      .replace('<plist version="1.0">', "<plist version='1.0'>");
    expect(await verifier()(await signed(payload))).toMatchObject({ challenge, udid });
  },
);
it('rejects duplicate discarded attributes and missing required challenge or UDID', async () => {
  const duplicate =
    '<key>MAC_ADDRESS_EN0</key><string>00:00:00:00:00:00</string><key>MAC_ADDRESS_EN0</key><string>11:11:11:11:11:11</string>';
  await expect(verifier()(await signed(xml(duplicate)))).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    verifier()(await signed(xml().replace('<key>CHALLENGE</key>', '<key>UNREQUESTED</key>'))),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    verifier()(await signed(xml().replace('<key>UDID</key>', '<key>UNREQUESTED</key>'))),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
});
it('bounds the number and length of ignored extra device attributes', async () => {
  const extra = Array.from(
    { length: 30 },
    (_, index) => `<key>EXTRA${index}</key><string>synthetic</string>`,
  ).join('');
  await expect(verifier()(await signed(xml(extra)))).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    verifier()(
      await signed(xml('<key>MAC_ADDRESS_EN0</key><string>' + 'x'.repeat(1025) + '</string>')),
    ),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
});

const modernVerifier = () =>
  deviceCollectionCms({
    policy: 'apple-profile-service',
    opensslPath: '/usr/bin/openssl',
    deviceCaPem: caPem,
    deviceCaSha256: caSha256,
  });
it('accepts the signed device claim under explicit Apple ProfileService policy with an opaque signer CN', async () => {
  expect(await modernVerifier()(await signed(xml(), 'modern.pem'))).toEqual({
    challenge,
    udid,
    product: 'iPhone15,2',
    signatureVerified: true,
    issuerTrusted: true,
    deviceCertificate: true,
  });
  await expect(verifier()(await signed(xml(), 'modern.pem'))).rejects.toThrow(
    'INVALID_DEVICE_CALLBACK',
  );
});
it('retains issuer trust and CMS signature checks under Apple ProfileService policy', async () => {
  await expect(
    deviceCollectionCms({ policy: 'apple-profile-service', opensslPath: '/usr/bin/openssl' })(
      await signed(xml(), 'modern.pem'),
    ),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  const modified = await signed(xml(), 'modern.pem');
  modified[modified.length - 1] ^= 1;
  await expect(modernVerifier()(modified)).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(modernVerifier()(Buffer.from(xml()))).rejects.toThrow('INVALID_DEVICE_CALLBACK');
});
it('requires a valid signed challenge and UDID under Apple ProfileService policy', async () => {
  await expect(
    modernVerifier()(
      await signed(xml().replace('<key>CHALLENGE</key>', '<key>UNREQUESTED</key>'), 'modern.pem'),
    ),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    modernVerifier()(
      await signed(xml().replace('<key>UDID</key>', '<key>UNREQUESTED</key>'), 'modern.pem'),
    ),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    modernVerifier()(await signed(xml('', 'not-a-device-udid'), 'modern.pem')),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
  await expect(
    modernVerifier()(await signed(xml().replace(challenge, 'too-short'), 'modern.pem')),
  ).rejects.toThrow('INVALID_DEVICE_CALLBACK');
});

it('preserves the nonempty device-certificate subject requirement in modern policy', async () => {
  await expect(modernVerifier()(await signed(xml(), 'empty.pem'))).rejects.toThrow(
    'INVALID_DEVICE_CALLBACK',
  );
});
