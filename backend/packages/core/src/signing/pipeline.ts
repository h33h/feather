import { normalizeSigningInput } from './normalization';
import { assertJobAccess } from '../apple/access-lifecycle';
import type { Database } from '../shared/database';
import { Failure } from '../shared/index';
import { normalizeUdid } from '../devices/onboarding';
import type { JobLeaseService } from './job-lifecycle';
import type { Publisher } from './publisher';
import type { ExecutorGrant, VerifiedReport } from '../shared/runner-contracts';
import type { DisposableExecutor, ExecutorProvider } from './executor-provider';
import type { StoragePort } from '../library/storage-contract';
import { buildPlan, type Component, type Profile } from './policy';
import type { MappingService } from './mapping';
import { createExecutorTask, validateSourceRemovals } from './executor-task';
import type { RemovedExtension, SigningWarning } from '../shared/signing-contracts';
import { diagnosticError } from './diagnostics';
export type AnalysisReport = ExecutorGrant & {
  protocolVersion: 1;
  operation: 'analysis';
  analysis: {
    sha256: string;
    bundleId: string;
    version: string;
    title: string;
    components: Component[];
    removedExtensions?: RemovedExtension[];
    warnings?: SigningWarning[];
  };
  executionAuthorized: false;
};
export interface AnalysisVm extends DisposableExecutor {
  analyze(input: {
    grant: ExecutorGrant;
    source: AsyncIterable<Uint8Array>;
    signal: AbortSignal;
  }): Promise<{
    report: AnalysisReport;
    attestation: string;
  }>;
}
export type PipelineProvisioner = (input: {
  grant: ExecutorGrant;
  analysis: AnalysisReport['analysis'];
  targets: Record<string, string>;
  signal: AbortSignal;
}) => Promise<
  Pick<Parameters<typeof createExecutorTask>[0], 'identity' | 'profiles' | 'udid' | 'deviceOs'>
>;
export type PipelineOptions = {
  db: Database;
  service: JobLeaseService;
  publisher: Publisher;
  storage: StoragePort;
  provider: ExecutorProvider;
  mapping: MappingService;
  attestor: {
    verify(report: AnalysisReport, attestation: string): Promise<boolean>;
  };
  provision: PipelineProvisioner;
  canPreserve: (grant: ExecutorGrant, bundleId: string) => Promise<boolean>;
  now?: () => number;
  maxRuntimeMs?: number;
};
/** Source parsing and cryptographic signing are confined to authenticated disposable guests. */
export class PipelineCoordinator {
  constructor(private o: PipelineOptions) {
    if (
      o.maxRuntimeMs !== undefined &&
      (!Number.isSafeInteger(o.maxRuntimeMs) || o.maxRuntimeMs < 1 || o.maxRuntimeMs > 15 * 60000)
    )
      throw new Failure('INVALID_EXECUTOR_DEADLINE');
  }
  private bounded<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
    return new Promise((resolve, reject) => {
      const stop = () => reject(new Failure('EXECUTOR_CANCELLED', 409));
      if (signal.aborted) {
        stop();
        return;
      }
      signal.addEventListener('abort', stop, { once: true });
      work.then(resolve, reject).finally(() => signal.removeEventListener('abort', stop));
    });
  }
  private now() {
    return (this.o.now ?? Date.now)();
  }
  private async guard(grant: ExecutorGrant) {
    await assertJobAccess(this.o.db, grant, this.now());
  }
  async kickoff(ownerId: string, jobId: string, deviceId: string) {
    const lease = await this.o.service.claim(jobId, ownerId),
      abort = new AbortController();
    let vm: AnalysisVm | undefined;
    let stage = 'bind-device';
    let timedOut = false;
    let destroyed = false;
    const destroy = async () => {
      if (vm && !destroyed) {
        await this.bounded(vm.destroy(), AbortSignal.timeout(30000));
        destroyed = true;
      }
    };
    const timer = setTimeout(
      () => {
        timedOut = true;
        abort.abort();
      },
      this.o.maxRuntimeMs ?? 15 * 60000,
    );
    timer.unref();
    const heartbeat = setInterval(() => {
      void this.o.service.heartbeat(jobId, ownerId, lease).catch(() => abort.abort());
    }, 20000);
    heartbeat.unref();
    try {
      const r = await this.o.db.query<{
        upload_id: string;
      }>(
        "UPDATE jobs j SET device_id=$3 WHERE j.id=$1 AND j.owner_id=$2 AND j.lease_token=$4 AND EXISTS(SELECT 1 FROM devices d JOIN apple_connections c ON c.id=d.connection_id AND c.owner_id=d.owner_id WHERE d.id=$3 AND d.owner_id=$2 AND d.status='ready' AND c.state='ready' AND c.provider='asc' AND d.connection_generation=c.generation AND j.connection_id=c.id AND j.connection_generation=c.generation) RETURNING upload_id",
        [jobId, ownerId, deviceId, lease],
      );
      if (!r.rows.length) throw new Failure('STALE_EXECUTOR_LEASE', 409);
      stage = 'launch';
      vm = (await this.bounded(
        this.o.provider
          .launch({
            ownerId,
            jobId,
            launchNonce: lease,
            signal: abort.signal,
            maxRuntimeMs: this.o.maxRuntimeMs ?? 15 * 60000,
            maxInputBytes: 1024 ** 3,
            maxUnpackedBytes: 4 * 1024 ** 3,
            maxEntries: 20000,
          })
          .then(async (instance) => {
            if (abort.signal.aborted) {
              await instance.destroy();
              throw new Failure('EXECUTOR_CANCELLED', 409);
            }
            return instance;
          }),
        abort.signal,
      )) as AnalysisVm;
      stage = 'verify-instance';
      if (
        !(await this.bounded(this.o.provider.verifyInstance(vm), abort.signal)) ||
        typeof vm.analyze !== 'function'
      )
        throw new Failure('TRUSTED_ANALYSIS_VM_REQUIRED', 503);
      stage = 'grant';
      const grant = await this.o.publisher.grant(
        ownerId,
        jobId,
        lease,
        vm.id,
        undefined,
        vm.expiresAt,
      );
      await this.guard(grant);
      stage = 'read-source';
      const source = await this.o.storage.read(ownerId, r.rows[0].upload_id);
      let result: Awaited<ReturnType<AnalysisVm['analyze']>>;
      try {
        stage = 'analyze';
        result = await this.bounded(
          vm.analyze({ grant, source: source.createReadStream(), signal: abort.signal }),
          abort.signal,
        );
      } finally {
        await source.close();
      }
      await this.guard(grant);
      stage = 'validate-analysis';
      if (abort.signal.aborted) throw new Failure('EXECUTOR_CANCELLED', 409);
      if (!(await this.o.attestor.verify(result.report, result.attestation)))
        throw new Failure('EXECUTOR_ATTESTATION_INVALID', 403);
      for (const k of Object.keys(grant) as (keyof ExecutorGrant)[])
        if (result.report[k] !== grant[k]) throw new Failure('EXECUTOR_BINDING_MISMATCH', 409);
      const a = result.report.analysis;
      if (
        result.report.protocolVersion !== 1 ||
        result.report.operation !== 'analysis' ||
        result.report.executionAuthorized !== false ||
        !a ||
        a.sha256 !== grant.uploadDigest ||
        !a.bundleId ||
        !a.title ||
        a.title.length > 200 ||
        !a.version ||
        a.version.length > 80 ||
        !Array.isArray(a.components) ||
        a.components.length > 20000
      )
        throw new Failure('ANALYSIS_REPORT_INVALID');
      if (
        a.components.some(
          (c) =>
            !c ||
            !['app', 'appex', 'framework', 'dylib'].includes(c.kind) ||
            typeof c.path !== 'string' ||
            typeof c.bundleId !== 'string' ||
            typeof c.minOs !== 'string' ||
            !/^\d+(\.\d+){1,2}$/.test(c.minOs) ||
            !Array.isArray(c.architectures) ||
            !c.entitlements ||
            typeof c.entitlements !== 'object' ||
            Array.isArray(c.entitlements),
        )
      )
        throw new Failure('ANALYSIS_REPORT_INVALID');
      validateSourceRemovals(a.components, a.removedExtensions);
      await this.o.db.query('UPDATE uploads SET metadata=$3 WHERE id=$1 AND owner_id=$2', [
        r.rows[0].upload_id,
        ownerId,
        JSON.stringify(a),
      ]);
      stage = 'preflight';
      const preflightIdentity = {
        ownerId,
        teamId: 'PREFLIGHT',
        prefix: 'PREFLIGHT',
        fingerprint: 'A'.repeat(40),
        expiresAt: this.now() + 60000,
      };
      const preflightProfiles: Record<string, Profile> = {};
      for (const component of a.components) {
        if (component.kind !== 'framework' && component.kind !== 'dylib')
          preflightProfiles[component.bundleId] = {
            ...preflightIdentity,
            bundleId: component.bundleId,
            udids: ['preflight'],
            entitlements: {
              'application-identifier': 'PREFLIGHT.' + component.bundleId,
              'com.apple.developer.team-identifier': 'PREFLIGHT',
              'get-task-allow': false,
            },
          };
      }
      buildPlan(
        normalizeSigningInput(a.components, {}, preflightProfiles, preflightIdentity).components,
        preflightIdentity,
        'preflight',
        preflightProfiles,
        this.now(),
        ownerId,
      );
      const devicePreflight = await this.o.db.query<{
        os_version: string | null;
      }>('SELECT os_version FROM devices WHERE id=$1 AND owner_id=$2', [grant.deviceId, ownerId]);
      const os = devicePreflight.rows[0]?.os_version;
      if (os && /^\d+(\.\d+){1,2}$/.test(os)) {
        const currentOs = os.split('.').map(Number);
        for (const component of a.components) {
          const minimum = component.minOs.split('.').map(Number);
          for (let part = 0; part < 3; part++) {
            if ((minimum[part] ?? 0) > (currentOs[part] ?? 0))
              throw new Failure('DEVICE_OS_TOO_OLD');
            if ((minimum[part] ?? 0) < (currentOs[part] ?? 0)) break;
          }
        }
      }
      const main = a.components.filter((c) => c.kind === 'app');
      if (main.length !== 1 || main[0].bundleId !== a.bundleId)
        throw new Failure('COMPONENT_GRAPH_REJECTED');
      stage = 'mapping';
      const mapping = await this.o.mapping.choose(
        ownerId,
        grant.connectionId,
        a.bundleId,
        await this.o.canPreserve(grant, a.bundleId),
      );
      const targets: Record<string, string> = { [a.bundleId]: mapping.target_id };
      for (const c of a.components.filter((c) => c.kind === 'appex')) {
        if (!c.bundleId.startsWith(a.bundleId + '.')) throw new Failure('EXTENSION_ID_MISMATCH');
        targets[c.bundleId] = await this.o.mapping.extension(
          ownerId,
          mapping.id,
          c.bundleId.slice(a.bundleId.length + 1),
        );
      }
      await this.guard(grant);
      await this.o.db.query("UPDATE jobs SET state='provisioning' WHERE id=$1 AND lease_token=$2", [
        jobId,
        lease,
      ]);
      stage = 'provision';
      const material = await this.bounded(
        this.o.provision({ grant, analysis: a, targets, signal: abort.signal }),
        abort.signal,
      );
      await this.guard(grant);
      const selected = await this.o.db.query<{
        udid: string;
        os_version: string | null;
      }>(
        "SELECT udid,os_version FROM devices WHERE id=$1 AND owner_id=$2 AND connection_id=$3 AND status='ready'",
        [grant.deviceId, ownerId, grant.connectionId],
      );
      if (
        !selected.rows[0]?.udid ||
        normalizeUdid(selected.rows[0].udid) !== normalizeUdid(material.udid) ||
        (selected.rows[0].os_version ?? null) !== (material.deviceOs ?? null)
      )
        throw new Failure('MATERIAL_DEVICE_MISMATCH', 409);
      stage = 'prepare-signing';
      const plan = createExecutorTask({
        ...material,
        ownerId,
        components: a.components,
        removedExtensions: a.removedExtensions,
        sourceWarnings: a.warnings,
        targets,

        now: this.now(),
      });
      await this.o.db.query('UPDATE jobs SET warnings=$3 WHERE id=$1 AND owner_id=$2', [
        jobId,
        ownerId,
        JSON.stringify(plan.warnings),
      ]);
      const signingGrant = await this.o.publisher.grant(
        ownerId,
        jobId,
        lease,
        vm.id,
        plan.planDigest,
        vm.expiresAt,
      );
      await this.o.db.query("UPDATE jobs SET state='signing' WHERE id=$1 AND lease_token=$2", [
        jobId,
        lease,
      ]);
      stage = 'sign';
      const signed = await this.bounded(
        vm.execute({ grant: signingGrant, task: plan.task, signal: abort.signal }),
        abort.signal,
      );
      await this.guard(signingGrant);
      const verifying = await this.o.db.query(
        "UPDATE jobs SET state='verifying',updated_at=$4 WHERE id=$1 AND owner_id=$2 AND lease_token=$3 AND lease_expires>$4 AND state='signing' RETURNING id",
        [jobId, ownerId, lease, this.now()],
      );
      if (!verifying.rows.length) throw new Failure('STALE_EXECUTOR_LEASE', 409);
      const bound = this.bounded.bind(this);
      const body = (async function* () {
        const iterator = signed.body[Symbol.asyncIterator]();
        try {
          for (;;) {
            const item = await bound(iterator.next(), abort.signal);
            if (item.done) break;
            if (abort.signal.aborted) throw new Failure('EXECUTOR_CANCELLED', 409);
            yield item.value;
          }
        } finally {
          void iterator.return?.();
          await destroy();
        }
      })();
      stage = 'publish';
      return await this.o.publisher.publish(
        signed.report as VerifiedReport,
        signed.attestation,
        body,
      );
    } catch (error) {
      console.error(
        JSON.stringify({
          event: 'signing_pipeline_failed',
          jobId,
          stage,
          instanceId: vm?.id,
          error: diagnosticError(error),
        }),
      );
      await destroy();
      if (stage === 'launch') await this.o.provider.retireLaunch(lease);
      const code = timedOut
        ? 'EXECUTOR_DEADLINE'
        : error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
          ? error.code
          : 'PIPELINE_FAILED';
      if (stage === 'launch' && code === 'RUNNER_BUSY') {
        await this.o.service.deferBusy({ ownerId, jobId, leaseToken: lease });
        throw error;
      }
      await this.o.service.finishAttempt(
        { ownerId, jobId, leaseToken: lease },
        { code, cancelled: !timedOut && code === 'EXECUTOR_CANCELLED' },
      );
      throw error;
    } finally {
      clearTimeout(timer);
      clearInterval(heartbeat);
      await destroy();
    }
  }
}
