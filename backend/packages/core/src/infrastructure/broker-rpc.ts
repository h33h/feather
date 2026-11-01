import { Readable } from 'node:stream';
import type { request as requestHttp } from 'undici';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Failure } from '../shared/index';
import { canonicalReport } from '../shared/canonical-json';
import type { ExecutorGrant } from '../shared/runner-contracts';
import type { BootstrapLease } from '../apple/onboarding';
import type { BrokerTransport, RunnerHttpOptions } from './runner-http';

export class ScopedBrokerRpc {
  constructor(private config: RunnerHttpOptions) {}
  async call<T>(
    operation: string,
    binding: ExecutorGrant | BootstrapLease | Record<string, unknown>,
    payload: unknown,
  ): Promise<T> {
    const controller = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new Failure('RUNNER_CONTROL_DEADLINE', 503));
      }, 60000);
    });
    const bounded = <V>(work: Promise<V>) => Promise.race([work, expired]);
    try {
      const response = await bounded(
        this.config.transport.request({
          url: new URL('/v1/control/' + operation, this.config.endpoint).toString(),
          method: 'POST',
          headers: {
            authorization: 'Bearer ' + this.config.token,
            'x-runner-audience': this.config.audience,
            'content-type': 'application/json',
          },
          body: canonicalReport({ binding, payload, audience: this.config.audience }),
          signal: controller.signal,
        }),
      );
      if (response.status !== 200) throw new Failure('RUNNER_CONTROL_UNAVAILABLE', 503);
      let size = 0;
      const parts: Buffer[] = [];
      const reader = response.body[Symbol.asyncIterator]();
      for (;;) {
        const item = await bounded(reader.next());
        if (item.done) break;
        const c = item.value;
        size += c.length;
        if (size > 4 * 1024 ** 2) throw new Failure('RUNNER_RESPONSE_TOO_LARGE', 502);
        parts.push(Buffer.from(c));
      }
      let envelope: {
        report: {
          binding: unknown;
          operation: string;
          audience: string;
          value: T;
        };
        attestation: string;
      };
      try {
        envelope = JSON.parse(Buffer.concat(parts).toString());
      } catch {
        throw new Failure('RUNNER_RESPONSE_INVALID', 502);
      }
      if (
        !envelope.report ||
        typeof envelope.attestation !== 'string' ||
        !/^[a-f0-9]{64}$/.test(envelope.attestation) ||
        !timingSafeEqual(
          createHmac('sha256', this.config.proofKey)
            .update(canonicalReport(envelope.report))
            .digest(),
          Buffer.from(envelope.attestation, 'hex'),
        ) ||
        envelope.report.operation !== operation ||
        envelope.report.audience !== this.config.audience ||
        canonicalReport(envelope.report.binding) !== canonicalReport(binding)
      )
        throw new Failure('RUNNER_CONTROL_PROOF_INVALID', 403);
      return envelope.report.value;
    } finally {
      if (timeout) clearTimeout(timeout);
      controller.abort();
    }
  }
}
/** Only the broker uses this transport. Request cancellation still belongs to the caller's lease budget. */
export function requestBrokerTransport(requester: typeof requestHttp): BrokerTransport {
  return {
    async request(input) {
      // Signing can legitimately consume the full 15-minute executor allowance.
      // Fetch has an independent five-minute headers ceiling; use the explicit
      // request API without changing global fetch or any authentication TTL.
      input.signal.throwIfAborted();
      const upload =
        typeof input.body === 'string'
          ? undefined
          : Readable.from(input.body, {
              objectMode: false,
              highWaterMark: 64 * 1024,
              signal: input.signal,
            });
      upload?.on('error', () => {}); // The requester observes stream errors; early connection rejection must also be safe.
      let response;
      try {
        response = await requester(input.url, {
          method: input.method,
          headers: input.headers,
          body: upload ?? (input.body as string),
          signal: input.signal,
          headersTimeout: 15 * 60000,
          bodyTimeout: 5 * 60000,
        });
      } catch (error) {
        upload?.destroy();
        throw error;
      }
      if (response.statusCode < 200 || response.statusCode >= 300) {
        // Undici couples a live upload's destruction to its response. Read the
        // bounded rejection first, then stop the source so its code survives.
        const parts: Buffer[] = [];
        let size = 0;
        try {
          if (response.statusCode < 300 || response.statusCode >= 400) {
            for await (const chunk of response.body) {
              size += chunk.length;
              if (size > 64 * 1024) throw new Failure('RUNNER_RESPONSE_TOO_LARGE', 502);
              parts.push(Buffer.from(chunk));
            }
          }
        } finally {
          response.body.destroy();
          upload?.destroy();
        }
        return {
          status: response.statusCode,
          body: (async function* () {
            yield Buffer.concat(parts);
          })(),
        };
      }
      return {
        status: response.statusCode,
        body: (async function* () {
          try {
            for await (const chunk of response.body) yield chunk;
          } finally {
            response.body.destroy();
          }
        })(),
      };
    },
  };
}
