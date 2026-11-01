import { ClientInstallations } from '../packages/core/src/application/client-installations';
import { LocalClientRelease } from '../packages/core/src/infrastructure/client-release';
import { Failure } from '../packages/core/src/shared/errors';
import { ConnectApple } from '../packages/core/src/application/connect-apple';
import { createNativeAuth } from '../packages/core/src/composition/native-runtime';
import { NativeApplication } from '../packages/core/src/application/native-application';
import { nativeCollectionSession } from '../packages/core/src/application/native-device-session';
import { FeatherSigningAssets } from '../packages/core/src/feather/signing-assets';
import { OpenSslSigningMaterial } from '../packages/core/src/feather/signing-material';
import { FeatherCatalog } from '../packages/core/src/catalog/feather-feed';
import { denyControlProfile } from '../packages/core/src/devices/eligibility';
import { ProfileDiagnostics } from '../packages/core/src/devices/profile-diagnostics';
import { createRunnerAuthorizer } from '../packages/core/src/application/request-runner-authorization';
import { InstallationHistory } from '../packages/core/src/library/installation-history';
import { ReceiveDeviceCallback } from '../packages/core/src/application/receive-device-callback';
import { RequestLifecycle } from '../packages/core/src/application/request-lifecycle';
import { RequestAuthorization } from '../packages/core/src/application/request-authorization';
import { JobRequests } from '../packages/core/src/application/job-requests';
import { ReceiveUpload } from '../packages/core/src/application/receive-upload';
import { RuntimeReadiness } from '../packages/core/src/application/runtime-readiness';
import { SigningReadiness } from '../packages/core/src/application/signing-readiness';
import { SigningExecution } from '../packages/core/src/application/signing-execution';
import { BootstrapConnection } from '../packages/core/src/application/bootstrap-connection';
import { BootstrapCertificates } from '../packages/core/src/application/bootstrap-certificates';
import { AppleClientCredentials } from '../packages/core/src/application/apple-client-credentials';
import { RuntimeQueries } from '../packages/core/src/application/queries';
import { cleanupHistory } from '../packages/core/src/library/installation-history';
import { request as brokerRequest } from 'undici';
import { DeviceCollection } from '../packages/core/src/devices/collection';
import { deviceCollectionCms } from '../packages/core/src/infrastructure/collection-cms';
import { AppleSharing } from '../packages/core/src/apple/access';
import { createPersonalRuntimeKernel } from '../packages/core/src/composition/personal-kernel';
import { BootstrapRenewal } from '../packages/core/src/apple/bootstrap-renewal';
import { Tickets } from '../packages/core/src/library/tickets';
import { Importer } from '../packages/core/src/catalog/importer';
import { providerRequest, boundedResponseText } from '../packages/core/src/infrastructure/config';
import { AppleClient, appleJwt } from '../packages/core/src/infrastructure/apple-api';
import { AppleOnboarding, DatabaseOnboardingPort } from '../packages/core/src/apple/onboarding';
import { deviceCmsRpc } from '../packages/core/src/infrastructure/cms-rpc';
import { DeviceOnboarding } from '../packages/core/src/devices/onboarding';
import { QueuedDispatcher } from '../packages/core/src/signing/queued-dispatcher';
import { ProductionProvisioner } from '../packages/core/src/signing/provisioner';
import { DeviceEligibilityProbe } from '../packages/core/src/devices/eligibility';
import { BootstrapSealing } from '../packages/core/src/apple/bootstrap-sealing';
import { JobsActions } from '../packages/core/src/signing/jobs-actions';
import {
  composeProductionPipeline,
  type ProductionPipelineConfig,
} from '../packages/core/src/composition/signing-runtime';
import {
  requestBrokerTransport,
  ScopedBrokerRpc,
} from '../packages/core/src/infrastructure/broker-rpc';
export const origin = process.env.ISIGN_ORIGIN ?? 'http://localhost:3000';
new URL(origin);
const transport = (url: string, init: RequestInit) => fetch(url, init);
function appleClient(
  key: Parameters<typeof appleJwt>[0],
  guard: () => Promise<void> = async () => {},
) {
  return new AppleClient(
    async (method, path) => {
      await guard();
      return appleJwt(key, method, path, Date.now() / 1000);
    },
    async (method, url, jwt, payload) =>
      providerRequest(
        transport,
        new URL(url),
        {
          method,
          headers: { Authorization: 'Bearer ' + jwt, 'Content-Type': 'application/json' },
          body: payload === undefined ? undefined : JSON.stringify(payload),
        },
        async (r) => ({
          status: r.status,
          data: await boundedResponseText(r, 4 * 1024 ** 2).then((text) => {
            try {
              return JSON.parse(text);
            } catch {
              return null;
            }
          }),
        }),
      ),
  );
}
async function production() {
  const kernel = await createPersonalRuntimeKernel({ env: process.env });
  const { db, service, storage, catalogs, artifacts, vault } = kernel;
  const nativeSessions = await createNativeAuth(db, process.env, origin).catch(async (error) => {
    await db.close();
    throw error;
  });
  const credentials = new AppleClientCredentials(db, vault, appleClient, Date.now);
  const certificates = new BootstrapCertificates(db, credentials.bootstrap.bind(credentials));
  const proofKey = process.env.ISIGN_RUNNER_PROOF_KEY;
  const bootstrapInputs =
    proofKey && /^[a-f0-9]{64}$/.test(proofKey)
      ? {
          db,
          sealing: new BootstrapSealing({
            vault,
            proofKey: Buffer.from(proofKey, 'hex'),
            audience: kernel.config.runner.audience,
          }),
          findCertificates: certificates.find.bind(certificates),
          createCertificate: certificates.create.bind(certificates),
        }
      : undefined;
  const nativeConfig: ProductionPipelineConfig | undefined =
    proofKey && /^[a-f0-9]{64}$/.test(proofKey)
      ? {
          endpoint: kernel.config.runner.origin,
          token: kernel.config.runner.token.reveal(),
          audience: kernel.config.runner.audience,
          proofKey: Buffer.from(proofKey, 'hex'),
          transport: requestBrokerTransport(brokerRequest),
          capabilities: {
            disposableAnalysis: true,
            guestSigning: true,
            sealedMaterials: true,
            appleProvisioning: true,
            bootstrap: true,
          },
        }
      : undefined;
  const planner = nativeConfig
    ? new ProductionProvisioner({
        db,
        api: credentials.job.bind(credentials),
        vault,
        rpc: new ScopedBrokerRpc(nativeConfig),
      })
    : undefined;
  const pipeline = composeProductionPipeline({
    kernel,
    transport: requestBrokerTransport(brokerRequest),
    env: process.env,
    bootstrap: bootstrapInputs,
    provision: planner?.provision,
    canPreserve: planner?.canPreserve.bind(planner),
  });
  const onboardingPort = new DatabaseOnboardingPort(db, vault);
  const bootstrapScenario = pipeline.bootstrap
    ? new BootstrapConnection(
        db,
        new BootstrapRenewal(db, Date.now),
        pipeline.bootstrap,
        onboardingPort,
        Date.now,
      )
    : undefined;
  const bootstrap = bootstrapScenario?.run.bind(bootstrapScenario);
  const execution = new SigningExecution(
    db,
    storage,
    artifacts,
    pipeline.kickoff,
    pipeline.retireLaunch,
  );
  const kickoff = pipeline.kickoff ? execution.run.bind(execution) : undefined;
  const retireLaunch = pipeline.retireLaunch ? execution.retireLaunch.bind(execution) : undefined;
  const dispatcher = new QueuedDispatcher(db, Date.now, kickoff);
  const jobs = new JobsActions(
    db,
    Date.now,
    pipeline.kickoff
      ? async (owner, job) => {
          await dispatcher.trigger(owner, job);
        }
      : undefined,
  );
  const enqueue = (owner: string, uploadId: string, key: string) =>
    jobs.ensure(owner, { uploadId, key });
  void service
    .recoverLeases(pipeline.retireExecutor, retireLaunch)
    .then(() => dispatcher.dispatch())
    .catch(() => {});
  const onboarding = new AppleOnboarding(
    onboardingPort,
    credentials.validateTeam.bind(credentials),
    Date.now,
  );
  const cms =
    process.env.ISIGN_DEVICE_POLICY_ID &&
    process.env.ISIGN_DEVICE_CA_SHA256 &&
    process.env.ISIGN_RUNNER_PROOF_KEY
      ? deviceCmsRpc({
          origin: kernel.config.runner.origin,
          authToken: kernel.config.runner.token.reveal(),
          audience: kernel.config.runner.audience,
          proofKey: Buffer.from(process.env.ISIGN_RUNNER_PROOF_KEY, 'hex'),
          policyId: process.env.ISIGN_DEVICE_POLICY_ID,
          caSha256: process.env.ISIGN_DEVICE_CA_SHA256,
          transport,
        })
      : undefined;
  const readyApi = credentials.ready.bind(credentials);
  const eligibility = new DeviceEligibilityProbe(db, Date.now, readyApi, pipeline.cmsVerifier);
  const collectionCms = deviceCollectionCms({
    policy: 'apple-profile-service',
    opensslPath: process.env.ISIGN_COLLECTION_OPENSSL ?? '/usr/bin/openssl',
    ...(process.env.ISIGN_COLLECTION_CA_PEM
      ? {
          deviceCaPem: process.env.ISIGN_COLLECTION_CA_PEM,
          deviceCaSha256: process.env.ISIGN_COLLECTION_CA_SHA256,
        }
      : {}),
  });
  const devices = new DeviceOnboarding(
    db,
    async (binding) => {
      return readyApi(
        binding,
        pipeline.cmsVerifier
          ? (resourceId, udid) => eligibility.check(binding, resourceId, udid)
          : undefined,
      );
    },
    Date.now,
    cms ?? collectionCms,
  );
  const collections = new DeviceCollection(
    db,
    devices,
    Date.now,
    collectionCms,
    nativeSessions ? nativeCollectionSession : undefined,
  );
  void collections.reconcileDue(20).catch(() => {});
  const tickets = new Tickets(db, Date.now, (owner, device, force) =>
    devices.checkRegistered(owner, device, force),
  );
  const signingReadiness = new SigningReadiness(db, bootstrap, collections, Date.now);
  const readiness = new RuntimeReadiness(
    db,
    kernel.kms,
    pipeline.kickoff,
    pipeline.checkReady,
    bootstrap,
  );
  const connectApple = new ConnectApple(onboarding, bootstrap);
  const receiveUpload = new ReceiveUpload(db, storage, jobs);
  const jobRequests = new JobRequests(db, jobs, devices);
  const authorization = new RequestAuthorization(db, Date.now);
  const clientInstaller = new ClientInstallations({
    db,
    release: new LocalClientRelease(process.env),
    jobs,
    receive: receiveUpload,
    authorization,
    devices,
    tickets,
    now: Date.now,
    ensureSigningReady: async (owner) => {
      if (!pipeline.kickoff) throw new Failure('NATIVE_PIPELINE_REQUIRED', 503);
      await signingReadiness.ensure(owner);
    },
  });
  const lifecycle = new RequestLifecycle(service, jobs, storage, artifacts);
  const queries = new RuntimeQueries(db, Date.now);
  const sharing = new AppleSharing(db, Date.now);
  const nativeAssets = nativeSessions
    ? new FeatherSigningAssets(db, {
        api: readyApi,
        vault,
        material: new OpenSslSigningMaterial(
          process.env.ISIGN_FEATHER_OPENSSL ?? '/usr/bin/openssl',
        ),
        verify: pipeline.cmsVerifier ?? denyControlProfile,
        now: Date.now,
      })
    : undefined;
  const nativeApplication =
    nativeSessions && nativeAssets
      ? new NativeApplication({
          auth: nativeSessions,
          queries,
          sharing,
          collections,
          devices,
          actions: service.devices,
          catalogs,
          catalog: new FeatherCatalog(db, catalogs, { now: Date.now }),
          assets: nativeAssets,
          admin: kernel.admin,
          connectApple: connectApple.run.bind(connectApple),
          disconnectApple: service.apple.disconnectFor.bind(service.apple),
          deleteAccount: lifecycle.deleteAccountFor.bind(lifecycle),
          bootstrap,
        })
      : undefined;
  const diagnostics =
    process.env.ISIGN_PROFILE_DIAGNOSTICS === '1'
      ? new ProfileDiagnostics(db, Date.now, '/state/isign/profile-diagnostics')
      : undefined;
  const deviceCallback = new ReceiveDeviceCallback(collections, devices, diagnostics);
  const runnerAuthorization = createRunnerAuthorizer(
    db,
    Date.now,
    process.env.ISIGN_RUNNER_AUDIENCE ?? '',
    proofKey,
  );
  return {
    clientInstaller,
    nativeSessions,
    nativeApplication,
    connectApple: connectApple.run.bind(connectApple),
    receiveUpload: receiveUpload.run.bind(receiveUpload),
    jobRequests,
    authorization,
    lifecycle,
    receiveDeviceCallback: deviceCallback.run.bind(deviceCallback),
    runnerAuthorization,
    history: new InstallationHistory(db, Date.now),
    backgroundTasks: [
      ...(nativeAssets
        ? [{ name: 'feather', intervalMs: 60000, run: () => nativeAssets.maintain() }]
        : []),
      {
        name: 'queue',
        intervalMs: 5000,
        run: () =>
          service
            .recoverLeases(pipeline.retireExecutor, retireLaunch)
            .then(() => dispatcher.dispatch()),
      },
      { name: 'devices', intervalMs: 15000, run: () => collections.reconcileDue(20) },
      {
        name: 'catalog',
        intervalMs: 60000,
        run: () => catalogs.ensureBuiltIns().then(() => catalogs.refreshDue()),
      },
      {
        name: 'lifecycle',
        intervalMs: 60000,
        run: () =>
          storage
            .recoverInterrupted()
            .then(() => storage.cleanup())
            .then(() => artifacts.cleanup())
            .then(() => service.recoverLeases(pipeline.retireExecutor, retireLaunch))
            .then(() => dispatcher.dispatch())
            .then(() => kernel.secretDeletionWorker.runOne())
            .then(() => cleanupHistory(db, Date.now())),
      },
    ],
    close: db.close.bind(db),
    service: {
      session: service.session.bind(service),
      authorizeWrite: service.authorizeWrite.bind(service),
      fresh: service.fresh.bind(service),
      logout: service.logout.bind(service),
      selectDevice: service.selectDevice.bind(service),
      removeDevice: service.removeDevice.bind(service),
      disconnect: service.disconnect.bind(service),
      devices: { removeIdentity: service.devices.removeIdentity.bind(service.devices) },
    },
    queries,
    catalogs,
    artifacts: { open: artifacts.open.bind(artifacts) },
    tickets,
    importer: new Importer(db, catalogs, storage, jobs),
    enqueue,
    jobs,
    bootstrap,
    ensureSigningReady: signingReadiness.ensure.bind(signingReadiness),
    auth: {
      rate: kernel.auth.rate.bind(kernel.auth),
      registrationOptions: kernel.auth.registrationOptions.bind(kernel.auth),
      register: kernel.auth.register.bind(kernel.auth),
      authenticationOptions: kernel.auth.authenticationOptions.bind(kernel.auth),
      authenticate: kernel.auth.authenticate.bind(kernel.auth),
      addOptions: kernel.auth.addOptions.bind(kernel.auth),
    },
    admin: kernel.admin,
    onboarding,
    devices,
    collections,
    sharing,
    readiness: async () => {
      await clientInstaller.assertReady();
      await readiness.check();
    },
    capabilities: {
      appleOnboarding: true,
      bootstrap: !!bootstrap,
      deviceEnrollment: true,
      runner: !!pipeline.kickoff,
    },
  };
}
export async function createRuntime() {
  return production();
}
export type Runtime = Awaited<ReturnType<typeof createRuntime>>;
