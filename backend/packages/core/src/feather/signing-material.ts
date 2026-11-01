import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, readFile, rm, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, createPrivateKey, createPublicKey, X509Certificate } from 'node:crypto';
import { Failure } from '../shared';
export interface SigningMaterial {
  generate(teamId: string): Promise<{ privateKey: Buffer; csr: string; spkiSha256: string }>;
  package(privateKey: Buffer, certificate: string, password: string): Promise<Buffer>;
}
const exec = promisify(execFile);
/** OpenSSL receives secrets only through mode-0600 files in a private temporary directory. */
export class OpenSslSigningMaterial implements SigningMaterial {
  constructor(private executable = 'openssl') {}
  private async temp<T>(work: (directory: string) => Promise<T>) {
    const directory = await mkdtemp(join(tmpdir(), 'isign-feather-'));
    try {
      await chmod(directory, 0o700);
      return await work(directory);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
  private async run(args: string[]) {
    try {
      await exec(this.executable, args, { timeout: 30000, maxBuffer: 1024 * 1024 });
    } catch {
      throw new Failure('SIGNING_MATERIAL_FAILED', 503);
    }
  }
  async generate(teamId: string) {
    if (!/^[A-Z0-9]{10}$/.test(teamId)) throw new Failure('INVALID_TEAM');
    return this.temp(async (dir) => {
      const key = join(dir, 'key.pem'),
        csr = join(dir, 'request.pem');
      await writeFile(key, '', { mode: 0o600 });
      await this.run([
        'req',
        '-new',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        key,
        '-out',
        csr,
        '-subj',
        '/CN=iSign Client/OU=' + teamId,
        '-sha256',
      ]);
      const privateKey = await readFile(key);
      try {
        return {
          privateKey,
          csr: await readFile(csr, 'utf8'),
          spkiSha256: createHash('sha256')
            .update(
              createPublicKey(createPrivateKey(privateKey)).export({ type: 'spki', format: 'der' }),
            )
            .digest('hex'),
        };
      } catch (error) {
        privateKey.fill(0);
        throw error;
      }
    });
  }
  async package(privateKey: Buffer, certificate: string, password: string) {
    if (!/^[A-Za-z0-9_-]{32,128}$/.test(password)) throw new Failure('INVALID_P12_PASSWORD');
    const cert = new X509Certificate(certificate);
    if (!cert.checkPrivateKey(createPrivateKey(privateKey)))
      throw new Failure('CERTIFICATE_IDENTITY_MISMATCH', 409);
    return this.temp(async (dir) => {
      await writeFile(join(dir, 'key'), privateKey, { mode: 0o600 });
      await writeFile(join(dir, 'cert'), certificate, { mode: 0o600 });
      await writeFile(join(dir, 'password'), password, { mode: 0o600 });
      await this.run([
        'pkcs12',
        '-export',
        '-inkey',
        join(dir, 'key'),
        '-in',
        join(dir, 'cert'),
        '-out',
        join(dir, 'identity.p12'),
        '-passout',
        'file:' + join(dir, 'password'),
        '-name',
        'iSign Client',
      ]);
      return readFile(join(dir, 'identity.p12'));
    });
  }
}
