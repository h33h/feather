import { execFile } from 'node:child_process';
import path from 'node:path';
import { z } from 'zod';
import { Failure } from '../shared/index';

const payloadSchema = z
  .array(
    z.object({
      AO1: z.enum(['SELF_SIGN', 'LINK']),
      AO4: z.string(),
      AO5: z.string(),
      AO6: z.string().nullish(),
      AO7: z.string().nullish(),
      AO8: z.string().nullish(),
    }),
  )
  .max(20000);

/** Only a downloaded publisher payload enters stdin. Raw mode skips link-map
 * resolution, so repository metadata cannot instruct the tool to fetch URLs. */
export async function decryptGBoxPayload(
  bytes: Buffer,
  binary = process.env.ISIGN_ISIGNKIT_PATH ?? path.resolve('backend/.tools/isignkit'),
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      binary,
      ['gbox', 'decrypt', '-', '--raw', '--gbox-version', '5.6.6'],
      {
        timeout: 20000,
        killSignal: 'SIGKILL',
        maxBuffer: 16 * 1024 ** 2,
        // Do not pass application credentials to the decoder.
        env: { PATH: process.env.PATH, LANG: 'C', TZ: 'UTC', NODE_ENV: 'production' },
      },
      (error, stdout) => {
        if (error) {
          const code = (error as NodeJS.ErrnoException).code;
          reject(
            new Failure(
              code === 'ENOENT'
                ? 'GBOX_DECODER_UNAVAILABLE'
                : error.killed && code !== 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
                  ? 'GBOX_DECRYPT_TIMEOUT'
                  : 'GBOX_DECRYPT_FAILED',
              502,
            ),
          );
          return;
        }
        try {
          const payload = payloadSchema.parse(JSON.parse(stdout));
          resolve(
            payload.map((app) => ({
              appName: app.AO4,
              appVersion: app.AO5,
              appImage: app.AO6 ?? undefined,
              appPackage: app.AO1 === 'SELF_SIGN' ? (app.AO7 ?? undefined) : undefined,
              appDescription: app.AO8 ?? undefined,
            })),
          );
        } catch {
          reject(new Failure('UNSUPPORTED_GBOX_SCHEMA'));
        }
      },
    );
    // An early tool exit can close stdin before a large feed is written. The
    // execFile callback owns that failure; EPIPE must not escape as an event.
    child.stdin?.on('error', () => {});
    child.stdin?.end(bytes);
  });
}
