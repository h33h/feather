import { createHmac, timingSafeEqual } from 'node:crypto';
import type { ExecutorGrant, VerifiedReport } from '../shared/runner-contracts';
import { canonicalReport } from '../shared/canonical-json';
import type { ExecutorProvider } from '../signing/executor-provider';
import type { AnalysisVm, AnalysisReport } from '../signing/pipeline';
import { Failure, token } from '../shared/index';
// Public IPA failures emitted only by the broker after guest response verification.
export const EXPECTED_RUNNER_FAILURE_CODES = [
  'SOURCE_LIMIT',
  'SOURCE_DIGEST_MISMATCH',
  'INPUT_TOO_LARGE',
  'ARCHIVE_INVALID',
  'ARCHIVE_LIMIT',
  'ARCHIVE_METADATA_LIMIT',
  'ZIP_PATH_REJECTED',
  'ZIP_ENTRY_REJECTED',
  'MAIN_APP_REQUIRED',
  'COMPONENT_GRAPH_REJECTED',
  'NESTED_APP_UNSUPPORTED',
  'UNMODELED_EXECUTABLE',
  'EXTENSION_ID_MISMATCH',
  'METADATA_LIMIT',
  'METADATA_INVALID',
  'BINARY_LIMIT',
  'MIN_OS_MISMATCH',
  'MACHO_BOUNDS',
  'MACHO_UNSUPPORTED',
  'FAT_BOUNDS',
  'FAT_METADATA_MISMATCH',
  'FAT_ARCHITECTURE_DUPLICATE',
  'FAT_ARCHITECTURE_MISMATCH',
  'ARCHITECTURE_UNSUPPORTED',
  'DYLIB_TYPE_REQUIRED',
  'SEGMENT_BOUNDS',
  'SECTION_BOUNDS',
  'PLATFORM_INVALID',
  'PLATFORM_UNSUPPORTED',
  'DRM_UNSUPPORTED',
  'SIGNATURE_BOUNDS',
  'ENTITLEMENTS_INVALID',
  'ENTITLEMENTS_MISMATCH',
  'ENTITLEMENTS_VALUE_UNSUPPORTED',
  'DER_ENTITLEMENTS_UNSUPPORTED',
  'LINUX_FAT_SOURCE_UNSUPPORTED',
  'LINUX_SOURCE_CAPACITY_UNSUPPORTED',
] as const;
const expectedFailures = new Set<string>(EXPECTED_RUNNER_FAILURE_CODES);
export interface BrokerTransport {
  request(input: {
    url: string;
    method: 'POST' | 'DELETE';
    headers: Record<string, string>;
    body: string | AsyncIterable<Uint8Array>;
    signal: AbortSignal;
  }): Promise<{
    status: number;
    body: AsyncIterable<Uint8Array>;
  }>;
}
export type RunnerHttpOptions = {
  endpoint: string;
  token: string;
  audience: string;
  proofKey: Buffer;
  transport: BrokerTransport;
  now?: () => number;
};
export class HttpRunnerProvider implements ExecutorProvider {
  private endpoint: string;
  constructor(private o: RunnerHttpOptions) {
    const u = new URL(o.endpoint);
    if (
      u.protocol !== 'https:' ||
      u.username ||
      u.password ||
      u.search ||
      u.hash ||
      u.pathname !== '/' ||
      o.token.length < 32 ||
      !o.audience ||
      o.proofKey.length < 32
    )
      throw new Failure('RUNNER_CONFIGURATION_INVALID', 503);
    this.endpoint = u.origin;
  }
  private headers() {
    return {
      authorization: 'Bearer ' + this.o.token,
      'x-runner-audience': this.o.audience,
      'content-type': 'application/json',
    };
  }
  private async read(response: { status: number; body: AsyncIterable<Uint8Array> }) {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of response.body) {
      size += c.length;
      if (size > (response.status >= 200 && response.status < 300 ? 4 * 1024 ** 2 : 64 * 1024))
        throw new Failure('RUNNER_RESPONSE_TOO_LARGE', 502);
      chunks.push(Buffer.from(c));
    }
    return Buffer.concat(chunks).toString();
  }
  private reject(status: number, value: unknown, fallback = 'RUNNER_REQUEST_REJECTED'): never {
    const code =
      value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 1
        ? (value as Record<string, unknown>).error
        : undefined;
    if (typeof code === 'string') {
      if (status === 422 && expectedFailures.has(code)) throw new Failure(code, 422);
      if (status === 413 && code === 'SOURCE_LIMIT') throw new Failure(code, 413);
      if (status === 409 && (code === 'RUNNER_BUSY' || code === 'SOURCE_DIGEST_MISMATCH'))
        throw new Failure(code, 409);
    }
    if (status === 429 || status >= 500) throw new Failure('RUNNER_TEMPORARY_UNAVAILABLE', 503);
    throw new Failure(
      fallback,
      fallback === 'RUNNER_REQUEST_REJECTED'
        ? 409
        : fallback === 'EXECUTOR_DESTRUCTION_FAILED'
          ? 503
          : 502,
    );
  }
  private async status(
    response: { status: number; body: AsyncIterable<Uint8Array> },
    expected: number,
    fallback: string,
  ) {
    const raw = await this.read(response);
    if (response.status === expected) return;
    let value: unknown;
    try {
      value = JSON.parse(raw);
    } catch {
      /* Only explicit structured failures are public. */
    }
    this.reject(response.status, value, fallback);
  }
  private async json(path: string, payload: unknown, signal: AbortSignal) {
    const response = await this.o.transport.request({
      url: this.endpoint + path,
      method: 'POST',
      headers: this.headers(),
      body: canonicalReport(payload),
      signal,
    });
    const raw = await this.read(response);
    let value: Record<string, unknown>;
    try {
      value = JSON.parse(raw);
    } catch {
      if (response.status === 429 || response.status >= 500)
        throw new Failure('RUNNER_TEMPORARY_UNAVAILABLE', 503);
      throw new Failure('RUNNER_RESPONSE_INVALID', 502);
    }
    if (response.status !== 200) this.reject(response.status, value);
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new Failure('RUNNER_RESPONSE_INVALID', 502);
    return value;
  }
  async retireLaunch(nonce: string) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(nonce)) throw new Failure('INVALID_EXECUTOR_NONCE');
    const response = await this.o.transport.request({
      url: this.endpoint + '/v1/retire-launch',
      method: 'POST',
      headers: this.headers(),
      body: canonicalReport({ nonce }),
      signal: AbortSignal.timeout(35000),
    });
    await this.status(response, 204, 'EXECUTOR_DESTRUCTION_FAILED');
  }

  private proof(report: unknown, signature: unknown) {
    if (typeof signature !== 'string' || !/^[a-f0-9]{64}$/.test(signature)) return false;
    return timingSafeEqual(
      createHmac('sha256', this.o.proofKey).update(canonicalReport(report)).digest(),
      Buffer.from(signature, 'hex'),
    );
  }
  async destroyInstance(instanceId: string) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(instanceId)) throw new Failure('INVALID_EXECUTOR_INSTANCE');
    const response = await this.o.transport.request({
      url: this.endpoint + '/v1/instances/' + instanceId,
      method: 'DELETE',
      headers: this.headers(),
      body: '{}',
      signal: AbortSignal.timeout(30000),
    });
    await this.status(response, 204, 'EXECUTOR_DESTRUCTION_FAILED');
  }
  private trusted = new WeakSet<object>();
  async verifyInstance(vm: object) {
    return this.trusted.has(vm);
  }
  async launch(input: Parameters<ExecutorProvider['launch']>[0]): Promise<AnalysisVm> {
    const nonce = input.launchNonce ?? token();
    const launched = await this.json(
      '/v1/instances',
      {
        ownerId: input.ownerId,
        jobId: input.jobId,
        maxRuntimeMs: input.maxRuntimeMs,
        maxInputBytes: input.maxInputBytes,
        maxUnpackedBytes: input.maxUnpackedBytes,
        maxEntries: input.maxEntries,
        nonce,
        audience: this.o.audience,
      },
      input.signal,
    );
    const report = launched.report as {
      id: string;
      ownerId: string;
      jobId: string;
      nonce: string;
      audience: string;
      disposable: boolean;
      expiresAt: number;
    };
    if (
      !report ||
      !this.proof(report, launched.attestation) ||
      report.ownerId !== input.ownerId ||
      report.jobId !== input.jobId ||
      report.nonce !== nonce ||
      report.audience !== this.o.audience ||
      report.disposable !== true ||
      !Number.isSafeInteger(report.expiresAt) ||
      report.expiresAt <= (this.o.now ?? Date.now)() ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(report.id)
    )
      throw new Failure('TRUSTED_VM_PROOF_REQUIRED', 403);
    let dead = false;
    const route = '/v1/instances/' + report.id;
    const guard = (grant: ExecutorGrant) => {
      if (
        dead ||
        grant.expiresAt > report.expiresAt ||
        grant.isolationInstanceId !== report.id ||
        grant.ownerId !== input.ownerId ||
        grant.jobId !== input.jobId ||
        input.signal.aborted ||
        grant.expiresAt <= (this.o.now ?? Date.now)()
      )
        throw new Failure('EXECUTOR_BINDING_MISMATCH', 409);
    };
    const vm: AnalysisVm = {
      id: report.id,
      expiresAt: report.expiresAt,
      analyze: async ({ grant, source, signal }) => {
        guard(grant);
        const uploaded = await this.o.transport.request({
          url: this.endpoint + route + '/source',
          method: 'POST',
          headers: {
            ...this.headers(),
            'content-type': 'application/octet-stream',
            'x-source-digest': grant.uploadDigest,
          },
          body: source,
          signal,
        });
        await this.status(uploaded, 204, 'RUNNER_SOURCE_REJECTED');
        const result = await this.json(route + '/analyze', { grant }, signal);
        if (!this.proof(result.report, result.attestation))
          throw new Failure('EXECUTOR_ATTESTATION_INVALID', 403);
        return { report: result.report as AnalysisReport, attestation: String(result.attestation) };
      },
      execute: async ({ grant, task, signal }) => {
        guard(grant);
        const result = await this.json(route + '/execute', { grant, task }, signal);
        if (
          !this.proof(result.report, result.attestation) ||
          !/^[A-Za-z0-9_-]{1,128}$/.test(String(result.artifactRef))
        )
          throw new Failure('EXECUTOR_ATTESTATION_INVALID', 403);
        const artifact = await this.o.transport.request({
          url: this.endpoint + route + '/artifacts/' + result.artifactRef,
          method: 'POST',
          headers: this.headers(),
          body: '{}',
          signal,
        });
        if (artifact.status !== 200)
          await this.status(artifact, 200, 'RUNNER_ARTIFACT_UNAVAILABLE');
        const body = (async function* () {
          let size = 0;
          for await (const c of artifact.body) {
            size += c.length;
            if (size > 1024 ** 3 || signal.aborted) throw new Failure('RUNNER_ARTIFACT_LIMIT', 502);
            yield c;
          }
        })();
        return {
          report: result.report as VerifiedReport,
          attestation: String(result.attestation),
          body,
        };
      },
      destroy: async () => {
        if (dead) return;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 30000);
        try {
          const response = await this.o.transport.request({
            url: this.endpoint + route,
            method: 'DELETE',
            headers: this.headers(),
            body: '{}',
            signal: controller.signal,
          });
          await this.status(response, 204, 'EXECUTOR_DESTRUCTION_FAILED');
          dead = true;
        } finally {
          clearTimeout(timer);
        }
      },
    };
    this.trusted.add(vm);
    return vm;
  }
}
