import { execFile } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';
import { normalizeUdid, type CmsVerifier } from '../devices/onboarding';
import { Failure } from '../shared/index';
/** Published by Apple for ProfileService, not downloaded or trusted from callback contents.
 * https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html
 * Unsupported newer device issuer keys fail closed until a reviewed deployment pin is supplied.
 */
export const APPLE_PROFILE_SERVICE_CA_PEM = `-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIBATANBgkqhkiG9w0BAQUFADB5MQswCQYDVQQGEwJVUzET
MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
biBBdXRob3JpdHkxLTArBgNVBAMTJEFwcGxlIGlQaG9uZSBDZXJ0aWZpY2F0aW9u
IEF1dGhvcml0eTAeFw0wNzA0MTYyMjU0NDZaFw0xNDA0MTYyMjU0NDZaMFoxCzAJ
BgNVBAYTAlVTMRMwEQYDVQQKEwpBcHBsZSBJbmMuMRUwEwYDVQQLEwxBcHBsZSBp
UGhvbmUxHzAdBgNVBAMTFkFwcGxlIGlQaG9uZSBEZXZpY2UgQ0EwgZ8wDQYJKoZI
hvcNAQEBBQADgY0AMIGJAoGBAPGUSsnquloYYK3Lok1NTlQZaRdZB2bLl+hmmkdf
Rq5nerVKc1SxywT2vTa4DFU4ioSDMVJl+TPhl3ecK0wmsCU/6TKqewh0lOzBSzgd
Z04IUpRai1mjXNeT9KD+VYW7TEaXXm6yd0UvZ1y8Cxi/WblshvcqdXbSGXH0KWO5
JQuvAgMBAAGjgZ4wgZswDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8w
HQYDVR0OBBYEFLL+ISNEhpVqedWBJo5zENinTI50MB8GA1UdIwQYMBaAFOc0Ki4i
3jlga7SUzneDYS8xoHw1MDgGA1UdHwQxMC8wLaAroCmGJ2h0dHA6Ly93d3cuYXBw
bGUuY29tL2FwcGxlY2EvaXBob25lLmNybDANBgkqhkiG9w0BAQUFAAOCAQEAd13P
Z3pMViukVHe9WUg8Hum+0I/0kHKvjhwVd/IMwGlXyU7DhUYWdja2X/zqj7W24Aq5
7dEKm3fqqxK5XCFVGY5HI0cRsdENyTP7lxSiiTRYj2mlPedheCn+k6T5y0U4Xr40
FXwWb2nWqCF1AgIudhgvVbxlvqcxUm8Zz7yDeJ0JFovXQhyO5fLUHRLCQFssAbf8
B4i8rYYsBUhYTspVJcxVpIIltkYpdIRSIARA49HNvKK4hzjzMS/OhKQpVKw+OCEZ
xptCVeN2pjbdt9uzi175oVo/u6B2ArKAW17u6XEHIdDMOe7cb33peVI6TD15W4MI
pyQPbp8orlXe+tA8JA==
-----END CERTIFICATE-----`;
export const APPLE_PROFILE_SERVICE_CA_SHA256 =
  '76f27d00e1333bc88de0e2916c38c9a7f2b75774c25a794c092a80e3c4c66cce';
export type DeviceCollectionCmsOptions = {
  opensslPath?: string;
  deviceCaPem?: string;
  deviceCaSha256?: string;
} & (
  | {
      policy: 'apple-profile-service';
      udidSubjectAttribute?: never;
    }
  | {
      policy?: 'udid-subject';
      udidSubjectAttribute: 'CN' | 'serialNumber' | 'UID';
    }
);
const run = promisify(execFile);
const invalid = () => new Failure('INVALID_DEVICE_CALLBACK', 400);
function xmlText(raw: string) {
  if (
    raw.length > 1024 ||
    /[<>\x00-\x08\x0b\x0c\x0e-\x1f]/.test(raw) ||
    /&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)/.test(raw)
  )
    throw invalid();
  return raw.replace(/&(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (entity) => {
    const standard: Record<string, string> = {
      '&amp;': '&',
      '&lt;': '<',
      '&gt;': '>',
      '&quot;': '"',
      '&apos;': "'",
    };
    if (standard[entity]) return standard[entity];
    const code = entity.startsWith('&#x')
      ? parseInt(entity.slice(3, -1), 16)
      : parseInt(entity.slice(2, -1), 10);
    if (
      !Number.isSafeInteger(code) ||
      code < 32 ||
      code > 0x10ffff ||
      (code >= 0xd800 && code <= 0xdfff)
    )
      throw invalid();
    return String.fromCodePoint(code);
  });
}
/** Parse a bounded flat ProfileService dictionary without resolving XML entities or external DTDs. */
function payload(bytes: Buffer) {
  if (!bytes.length || bytes.length > 65536) throw invalid();
  let source = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
  source = source.replace(
    /^<\?xml\s+version\s*=\s*(["'])1\.0\1(?:\s+encoding\s*=\s*(["'])UTF-8\2)?(?:\s+standalone\s*=\s*(["'])(?:yes|no)\3)?\s*\?>\s*/i,
    '',
  );
  source = source.replace(
    /^<!DOCTYPE\s+plist\s+PUBLIC\s+(["'])-\/\/Apple(?: Computer| Inc)?\/\/DTD PLIST 1\.0\/\/EN\1\s+(["'])http:\/\/www\.apple\.com\/DTDs\/PropertyList-1\.0\.dtd\2\s*>\s*/,
    '',
  );
  const root =
    /^<plist\s+version\s*=\s*(["'])1\.0\1\s*>\s*<dict>([\s\S]*)<\/dict>\s*<\/plist>$/.exec(source);
  if (!root) throw invalid();
  const pairs = root[2];
  const values: Record<string, string> = {};
  const keys = new Set<string>();
  let offset = 0;
  const pair = /\s*<key>([^<>]*)<\/key>\s*<(string|data)>([^<>]*)<\/\2>\s*/gy;
  while (offset < pairs.length) {
    pair.lastIndex = offset;
    const next = pair.exec(pairs);
    if (!next) {
      if (pairs.slice(offset).trim() === '') break;
      throw invalid();
    }
    offset = pair.lastIndex;
    const key = xmlText(next[1]);
    if (!key || key.length > 128 || keys.has(key) || keys.size >= 32) throw invalid();
    keys.add(key);
    let value = xmlText(next[3]);
    // iOS may include additional signed attributes; do not retain or expose them.
    if (!['CHALLENGE', 'UDID', 'PRODUCT', 'VERSION'].includes(key)) continue;
    if (next[2] === 'data') {
      if (key !== 'CHALLENGE') throw invalid();
      value = value.replace(/\s/g, '');
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
        throw invalid();
      value = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(value, 'base64'));
    }
    if (!value) throw invalid();
    values[key] = value;
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(values.CHALLENGE ?? '')) throw invalid();
  const udid = normalizeUdid(values.UDID ?? '');
  if (values.PRODUCT !== undefined && !/^iPhone\d{1,3},\d{1,3}$/.test(values.PRODUCT))
    throw invalid();
  // VERSION has historically been a build number; do not invent an iOS version from it.
  const version =
    values.VERSION !== undefined && /^\d{1,2}(?:\.\d{1,2}){1,2}$/.test(values.VERSION)
      ? values.VERSION
      : undefined;
  if (
    values.VERSION !== undefined &&
    version === undefined &&
    !/^\d{1,3}[A-Z]\d{1,4}[a-z]?$/.test(values.VERSION)
  )
    throw invalid();
  return {
    challenge: values.CHALLENGE,
    udid,
    ...(values.PRODUCT ? { product: values.PRODUCT } : {}),
    ...(version ? { version } : {}),
  };
}
/** CA overrides and leaf policy are server deployment configuration, never request inputs.
 * Apple's published ProfileService policy explicitly ignores device certificate validity dates.
 * Both policies verify the CMS signature, issuer signature, exact CA pin and non-CA device signer.
 * Apple ProfileService authenticates the signed device claims; its device-certificate policy
 * does not require the certificate CN to equal the UDID in the signed payload.
 * https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecPolicy.c
 */
export function deviceCollectionCms(options: DeviceCollectionCmsOptions): CmsVerifier {
  if (!options) throw new Failure('CMS_DEVICE_POLICY_REQUIRED', 503);
  const policy = options.policy ?? 'udid-subject';
  if (
    !['apple-profile-service', 'udid-subject'].includes(policy) ||
    (policy === 'udid-subject' &&
      !['CN', 'serialNumber', 'UID'].includes(options.udidSubjectAttribute ?? ''))
  )
    throw new Failure('CMS_DEVICE_POLICY_REQUIRED', 503);
  const attribute = options.udidSubjectAttribute;
  const openssl = options.opensslPath ?? '/usr/bin/openssl';
  if (!isAbsolute(openssl) || Boolean(options.deviceCaPem) !== Boolean(options.deviceCaSha256))
    throw new Failure('CMS_CONFIGURATION_INVALID', 503);
  let ca: X509Certificate;
  try {
    ca = new X509Certificate(options.deviceCaPem ?? APPLE_PROFILE_SERVICE_CA_PEM);
  } catch {
    throw new Failure('CMS_CONFIGURATION_INVALID', 503);
  }
  const fingerprint = options.deviceCaSha256 ?? APPLE_PROFILE_SERVICE_CA_SHA256;
  if (
    !ca.ca ||
    !/^[a-f0-9]{64}$/.test(fingerprint) ||
    createHash('sha256').update(ca.raw).digest('hex') !== fingerprint
  )
    throw new Failure('CMS_CONFIGURATION_INVALID', 503);
  let active = 0;
  return async (body) => {
    if (!body.length || body.length > 65536) throw invalid();
    if (active >= 4) throw new Failure('CMS_VERIFIER_BUSY', 429);
    active++;
    let directory: string | undefined;
    try {
      directory = await mkdtemp(join(tmpdir(), 'isign-device-cms-'));
      await chmod(directory, 0o700);
      const input = join(directory, 'input.cms'),
        signer = join(directory, 'signer.pem'),
        content = join(directory, 'payload.plist');
      await writeFile(input, body, { mode: 0o600 });
      // -noverify defers certificate trust to the explicit pinned issuer check below.
      // It does not disable the CMS content/signature checks; neither -nosigs nor -no_content_verify is used.
      await run(
        openssl,
        [
          'cms',
          '-verify',
          '-inform',
          'DER',
          '-binary',
          '-noverify',
          '-in',
          input,
          '-signer',
          signer,
          '-out',
          content,
        ],
        { timeout: 10000, maxBuffer: 65536, windowsHide: true },
      );
      const pem = await readFile(signer, 'utf8');
      const certificates = pem.match(
        /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
      );
      if (certificates?.length !== 1 || pem.replace(certificates[0], '').trim()) throw invalid();
      const leaf = new X509Certificate(certificates[0]);
      if (
        leaf.ca ||
        !leaf.subject.trim() ||
        leaf.issuer !== ca.subject ||
        !leaf.checkIssued(ca) ||
        !leaf.verify(ca.publicKey)
      )
        throw invalid();
      const signed = payload(await readFile(content));
      if (policy === 'udid-subject') {
        const subjects = leaf.subject
          .split('\n')
          .filter((line) => line.startsWith(attribute + '='))
          .map((line) => line.slice(attribute!.length + 1));
        if (subjects.length !== 1 || normalizeUdid(subjects[0]) !== signed.udid) throw invalid();
      }
      return { ...signed, signatureVerified: true, issuerTrusted: true, deviceCertificate: true };
    } catch (error) {
      if (
        (error as NodeJS.ErrnoException)?.code &&
        ['ENOENT', 'EACCES', 'ENOEXEC'].includes((error as NodeJS.ErrnoException).code!) &&
        directory !== undefined
      )
        throw new Failure('CMS_VERIFIER_UNAVAILABLE', 503);
      if (error instanceof Failure && error.message === 'CMS_VERIFIER_BUSY') throw error;
      throw invalid();
    } finally {
      active--;
      if (directory) await rm(directory, { recursive: true, force: true });
    }
  };
}
