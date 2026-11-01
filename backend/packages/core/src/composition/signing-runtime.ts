import { ScopedBrokerRpc } from '../infrastructure/broker-rpc';
import { createHash } from 'node:crypto';
import type { Database } from '../shared/database';
import type { ControlProfileVerifier } from '../devices/eligibility';
import type { JobLeaseService } from '../signing/job-lifecycle';
import { Failure, token } from '../shared/index';
import { Publisher, HmacExecutorAttestor, type ArtifactStore } from '../signing/publisher';
import type { ExecutorGrant } from '../shared/runner-contracts';
import type { StoragePort } from '../library/storage-contract';
import { MappingService } from '../signing/mapping';
import {
  PipelineCoordinator,
  type PipelineProvisioner,
  type AnalysisReport,
} from '../signing/pipeline';
import {
  HttpRunnerProvider,
  type BrokerTransport,
  type RunnerHttpOptions,
} from '../infrastructure/runner-http';
import { DatabaseBootstrapPort } from '../apple/bootstrap-store';
import { TeamBootstrap, type BootstrapLease, type BootstrapIdentity } from '../apple/onboarding';
/** These capabilities are explicit deployment opt-ins, not inferred from an endpoint existing. */
export type ProductionPipelineConfig = RunnerHttpOptions & {
  capabilities: {
    disposableAnalysis: true;
    guestSigning: true;
    sealedMaterials: true;
    appleProvisioning: true;
    bootstrap: true;
  };
  maxRuntimeMs?: number;
};
type Inputs = {
  db: Database;
  service: JobLeaseService;
  storage: StoragePort;
  artifactStore: ArtifactStore;
  now?: () => number;
  provision: PipelineProvisioner;
  canPreserve: (grant: ExecutorGrant, bundleId: string) => Promise<boolean>;
};
export function createProductionPipeline(input: Inputs, config: ProductionPipelineConfig) {
  if (
    !config.capabilities ||
    Object.values(config.capabilities).some((x) => x !== true) ||
    Object.keys(config.capabilities).length !== 5
  )
    throw new Failure('NATIVE_PIPELINE_CAPABILITIES_REQUIRED', 503);
  const provider = new HttpRunnerProvider(config),
    attestor = new HmacExecutorAttestor(config.proofKey),
    rpc = new ScopedBrokerRpc(config),
    publisher = new Publisher(input.db, input.artifactStore, attestor, input.now ?? Date.now);
  const coordinator = new PipelineCoordinator({
    db: input.db,
    service: input.service,
    storage: input.storage,
    publisher,
    provider,
    mapping: new MappingService(input.db),
    attestor: {
      verify: (report: AnalysisReport, signature: string) =>
        attestor.verify(report as never, signature),
    },
    provision: input.provision,
    canPreserve: input.canPreserve,
    now: input.now,
    maxRuntimeMs: config.maxRuntimeMs,
  });
  const checkReady = async () => {
    const protocols = await rpc.call<{
      runner: string;
      provisioning: string;
      materials: string;
      executorReady: boolean;
    }>('capabilities', { nonce: token() }, {});
    if (
      protocols.runner !== 'isign-native-v1' ||
      protocols.provisioning !== 'isign-provisioning-v1' ||
      protocols.materials !== 'isign-sealed-materials-v1' ||
      protocols.executorReady !== true
    )
      throw new Failure('NATIVE_PIPELINE_PROTOCOL_UNSUPPORTED', 503);
  };
  const kickoff = async (ownerId: string, jobId: string, deviceId: string) => {
    await checkReady();
    return coordinator.kickoff(ownerId, jobId, deviceId);
  };
  return {
    checkReady,
    kickoff,
    coordinator,
    publisher,
    retireLaunch: (nonce: string) => provider.retireLaunch(nonce),
    retireExecutor: (grant: ExecutorGrant) => provider.destroyInstance(grant.isolationInstanceId),
  };
}
/** Runtime-facing composition; missing transport/protocol configuration remains fail closed. */
export function composeProductionPipeline(input: {
  kernel: {
    db: Database;
    jobs: JobLeaseService;
    storage: StoragePort;
    artifacts: ArtifactStore;
  };
  transport: BrokerTransport;
  env: Record<string, string | undefined>;
  bootstrap?: Parameters<typeof createProductionBootstrap>[0];
  provision?: PipelineProvisioner;
  canPreserve?: (grant: ExecutorGrant, bundleId: string) => Promise<boolean>;
}) {
  const e = input.env;
  const required = [
    'ISIGN_RUNNER_ORIGIN',
    'ISIGN_RUNNER_TOKEN',
    'ISIGN_RUNNER_AUDIENCE',
    'ISIGN_RUNNER_PROOF_KEY',
    'ISIGN_RUNNER_PROTOCOL',
    'ISIGN_PROVISIONING_PROTOCOL',
    'ISIGN_MATERIAL_PROTOCOL',
  ];
  const missing = required.filter((name) => !e[name]);
  if (missing.length)
    return { diagnostics: ['NATIVE_PIPELINE_UNAVAILABLE: ' + missing.join(', ')] };
  if (
    e.ISIGN_RUNNER_PROTOCOL !== 'isign-native-v1' ||
    e.ISIGN_PROVISIONING_PROTOCOL !== 'isign-provisioning-v1' ||
    e.ISIGN_MATERIAL_PROTOCOL !== 'isign-sealed-materials-v1' ||
    !/^[a-f0-9]{64}$/.test(e.ISIGN_RUNNER_PROOF_KEY!)
  )
    return { diagnostics: ['NATIVE_PIPELINE_PROTOCOL_UNSUPPORTED'] };
  const config: ProductionPipelineConfig = {
    endpoint: e.ISIGN_RUNNER_ORIGIN!,
    token: e.ISIGN_RUNNER_TOKEN!,
    audience: e.ISIGN_RUNNER_AUDIENCE!,
    proofKey: Buffer.from(e.ISIGN_RUNNER_PROOF_KEY!, 'hex'),
    transport: input.transport,
    capabilities: {
      disposableAnalysis: true,
      guestSigning: true,
      sealedMaterials: true,
      appleProvisioning: true,
      bootstrap: true,
    },
  };
  if (!input.provision || !input.canPreserve)
    return { diagnostics: ['PRODUCTION_PROVISIONER_UNAVAILABLE'] };
  const pipeline = createProductionPipeline(
    {
      db: input.kernel.db,
      service: input.kernel.jobs,
      storage: input.kernel.storage,
      artifactStore: input.kernel.artifacts,
      provision: input.provision,
      canPreserve: input.canPreserve,
    },
    config,
  );
  const bootstrap = input.bootstrap
    ? createProductionBootstrap(input.bootstrap, config)
    : undefined;
  return {
    kickoff: pipeline.kickoff,
    checkReady: pipeline.checkReady,
    bootstrap,
    retireExecutor: pipeline.retireExecutor,
    retireLaunch: pipeline.retireLaunch,
    cmsVerifier: createProductionDeviceVerifier(config),
    diagnostics: [
      ...(bootstrap
        ? []
        : [
            'BOOTSTRAP_UNAVAILABLE: authenticated guest-to-local-Vault sealing bridge is not configured',
          ]),
    ],
  };
}
export interface BootstrapEnvelopeBridge {
  issue(
    lease: BootstrapLease,
    purpose: 'distribution-key',
    instanceId: string,
    maxExpiresAt?: number,
  ): Promise<{
    grant: unknown;
    dataKey: Buffer;
  }>;
  commit(lease: BootstrapLease, receipt: never): Promise<BootstrapIdentity>;
}
export function createProductionBootstrap(
  input: {
    db: Database;
    sealing: BootstrapEnvelopeBridge;
    findCertificates: (
      lease: BootstrapLease,
      spki: string,
    ) => Promise<
      {
        id: string;
        certificate: string;
      }[]
    >;
    createCertificate: (
      lease: BootstrapLease,
      csr: string,
    ) => Promise<{
      id: string;
      certificate: string;
    }>;
    now?: () => number;
  },
  config: ProductionPipelineConfig,
) {
  const provider = new HttpRunnerProvider(config),
    rpc = new ScopedBrokerRpc(config);
  const port = new DatabaseBootstrapPort({
    db: input.db,
    now: input.now,
    findCertificates: input.findCertificates,
    createCertificate: input.createCertificate,
    prepareIdentity: async (lease) => {
      const controller = new AbortController();
      let timeout: ReturnType<typeof setTimeout> | undefined;
      const expired = new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(new Failure('BOOTSTRAP_EXECUTOR_DEADLINE', 503));
        }, 120000);
      });
      const bound = <V>(work: Promise<V>) => Promise.race([work, expired]);
      let vm: Awaited<ReturnType<HttpRunnerProvider['launch']>> | undefined;
      let dataKey: Buffer | undefined;
      try {
        vm = await bound(
          provider
            .launch({
              ownerId: lease.ownerId,
              jobId: 'bootstrap:' + lease.nonce,
              launchNonce: token(),
              signal: controller.signal,
              maxRuntimeMs: 120000,
              maxInputBytes: 16384,
              maxUnpackedBytes: 16384,
              maxEntries: 1,
            })
            .then(async (guest) => {
              if (controller.signal.aborted) {
                await guest.destroy();
                throw new Failure('BOOTSTRAP_EXECUTOR_DEADLINE', 503);
              }
              return guest;
            }),
        );
        if (!(await bound(provider.verifyInstance(vm!))))
          throw new Failure('TRUSTED_VM_PROOF_REQUIRED', 403);
        await port.assertCurrent(lease);
        const issued = await bound(
          input.sealing.issue(lease, 'distribution-key', vm!.id, vm!.expiresAt),
        );
        dataKey = issued.dataKey;
        if (dataKey.length !== 32) throw new Failure('BOOTSTRAP_SEALING_KEY_INVALID', 503);
        const receipt = await bound(
          rpc.call<never>('bootstrap-prepare', lease, {
            instanceId: vm!.id,
            sealGrant: issued.grant,
            dataKey: dataKey.toString('base64'),
          }),
        );
        dataKey.fill(0);
        await port.assertCurrent(lease);
        return await bound(input.sealing.commit(lease, receipt));
      } finally {
        dataKey?.fill(0);
        if (timeout) clearTimeout(timeout);
        controller.abort();
        if (vm) {
          let cleanup: ReturnType<typeof setTimeout> | undefined;
          try {
            await Promise.race([
              vm.destroy(),
              new Promise<never>((_, reject) => {
                cleanup = setTimeout(
                  () => reject(new Failure('EXECUTOR_DESTRUCTION_FAILED', 503)),
                  30000,
                );
              }),
            ]);
          } finally {
            if (cleanup) clearTimeout(cleanup);
          }
        }
      }
    },
  });
  return new TeamBootstrap(port, input.now ?? Date.now);
}
export function createProductionDeviceVerifier(
  config: ProductionPipelineConfig,
): ControlProfileVerifier {
  const provider = new HttpRunnerProvider(config),
    rpc = new ScopedBrokerRpc(config);
  return async (input) => {
    if (
      input.cms.length > 65536 ||
      input.cms.length < 1 ||
      createHash('sha256').update(input.cms).digest('hex') !== input.cmsSha256
    )
      throw new Failure('CONTROL_PROFILE_DIGEST_MISMATCH', 403);
    const access = input.binding;
    const shared = access.ownerId !== access.connectionOwnerId;
    if (
      shared &&
      (typeof access.accessGrantId !== 'string' ||
        !access.accessGrantId ||
        !Number.isSafeInteger(access.accessGrantGeneration) ||
        (access.accessGrantGeneration ?? 0) < 1)
    )
      throw new Failure('APPLE_ACCESS_UNAVAILABLE', 403);
    if (!shared && (access.accessGrantId != null || access.accessGrantGeneration != null))
      throw new Failure('APPLE_ACCESS_UNAVAILABLE', 403);
    const nonce = token(),
      binding = {
        ownerId: access.ownerId,
        connectionOwnerId: access.connectionOwnerId,
        connectionId: access.connectionId,
        generation: access.generation,
        nonce,
        expiresAt: Date.now() + 120000,
        ...(shared
          ? {
              accessGrantId: access.accessGrantId,
              accessGrantGeneration: access.accessGrantGeneration,
            }
          : {}),
      };
    const controller = new AbortController();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const expired = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        controller.abort();
        reject(new Failure('DEVICE_VERIFIER_DEADLINE', 503));
      }, 120000);
    });
    const bounded = <V>(work: Promise<V>) => Promise.race([work, expired]);
    let vm: Awaited<ReturnType<HttpRunnerProvider['launch']>> | undefined;
    try {
      vm = await bounded(
        provider
          .launch({
            ownerId: binding.ownerId,
            jobId: 'device-eligibility:' + nonce,
            launchNonce: nonce,
            signal: controller.signal,
            maxRuntimeMs: 120000,
            maxInputBytes: 65536,
            maxUnpackedBytes: 65536,
            maxEntries: 1,
          })
          .then(async (guest) => {
            if (controller.signal.aborted) {
              await guest.destroy();
              throw new Failure('DEVICE_VERIFIER_DEADLINE', 503);
            }
            return guest;
          }),
      );
      if (!(await bounded(provider.verifyInstance(vm!))))
        throw new Failure('TRUSTED_VM_PROOF_REQUIRED', 403);
      const result = await bounded(
        rpc.call<{
          digest: string;
          teamId: string;
          bundleId: string;
          devices: string[];
          certificates: string[];
          expiresAt: number;
          profileType: 'ad-hoc';
          entitlements?: Record<string, unknown>;
        }>('device-profile-verify', binding, {
          instanceId: vm!.id,
          cmsBase64: input.cms.toString('base64'),
          expected: input.expected,
        }),
      );
      if (
        result.digest !== input.cmsSha256 ||
        result.teamId !== input.expected.teamId ||
        result.bundleId !== input.expected.bundleId ||
        !Array.isArray(result.devices) ||
        !result.devices.includes(input.expected.udid) ||
        !Array.isArray(result.certificates) ||
        !result.certificates.includes(input.expected.certificateSha256) ||
        result.profileType !== 'ad-hoc' ||
        !Number.isSafeInteger(result.expiresAt) ||
        result.expiresAt <= input.now
      )
        throw new Failure('CONTROL_PROFILE_PIN_MISMATCH', 403);
      return {
        cmsSha256: result.digest,
        teamId: result.teamId,
        bundleId: result.bundleId,
        deviceUdids: result.devices,
        certificateSha256s: result.certificates,
        expiresAt: result.expiresAt,
        profileType: result.profileType,
        ...(result.entitlements ? { entitlements: result.entitlements } : {}),
      };
    } finally {
      if (timeout) clearTimeout(timeout);
      controller.abort();
      if (vm) {
        let cleanup: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            vm.destroy(),
            new Promise<never>((_, reject) => {
              cleanup = setTimeout(
                () => reject(new Failure('EXECUTOR_DESTRUCTION_FAILED', 503)),
                30000,
              );
            }),
          ]);
        } finally {
          if (cleanup) clearTimeout(cleanup);
        }
      }
    }
  };
}
