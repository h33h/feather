import { ClientInstallations } from '../packages/core/src/application/client-installations';
import { LocalClientRelease } from '../packages/core/src/infrastructure/client-release';
import { Failure } from '../packages/core/src/shared/errors';
import { ConnectApple } from '../packages/core/src/application/connect-apple';
import { NativeSessions } from '../packages/core/src/auth/native-sessions';
import { NativeApplication } from '../packages/core/src/application/native-application';
import { nativeCollectionSession } from '../packages/core/src/application/native-device-session';
import { FeatherSigningAssets } from '../packages/core/src/feather/signing-assets';
import { OpenSslSigningMaterial } from '../packages/core/src/feather/signing-material';
import { FeatherCatalog } from '../packages/core/src/catalog/feather-feed';
import { denyControlProfile } from '../packages/core/src/devices/eligibility';
import { ProfileDiagnostics } from '../packages/core/src/devices/profile-diagnostics';
import { createRunnerAuthorizer } from '../packages/core/src/application/request-runner-authorization';
import { ReceiveDeviceCallback } from '../packages/core/src/application/receive-device-callback';
import { RequestLifecycle } from '../packages/core/src/application/request-lifecycle';
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
import { providerRequest, boundedResponseText } from '../packages/core/src/infrastructure/config';
import { AppleClient, appleJwt } from '../packages/core/src/infrastructure/apple-api';
import { AppleOnboarding, DatabaseOnboardingPort } from '../packages/core/src/apple/onboarding';
import { DeviceOnboarding } from '../packages/core/src/devices/onboarding';
import { QueuedDispatcher } from '../packages/core/src/signing/queued-dispatcher';
import { ProductionProvisioner } from '../packages/core/src/signing/provisioner';
import { DeviceEligibilityProbe } from '../packages/core/src/devices/eligibility';
import { BootstrapSealing } from '../packages/core/src/apple/bootstrap-sealing';
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
  let dispatcher: QueuedDispatcher;
  const kernel = await createPersonalRuntimeKernel({
    env: process.env,
    onSourceReady: (owner, job) => dispatcher.trigger(owner, job),
  });
  const {
    db,
    sessions,
    accounts,
    connections,
    deviceActions,
    storage,
    catalogs,
    artifacts,
    vault,
    jobs,
  } = kernel;
  const nativeSessions = new NativeSessions(db, {
    origin,
    callback: 'isign-feather://auth/callback',
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
  dispatcher = new QueuedDispatcher(db, Date.now, kickoff);
  void jobs
    .recoverLeases(pipeline.retireExecutor, retireLaunch)
    .then(() => dispatcher.dispatch())
    .catch(() => {});
  const onboarding = new AppleOnboarding(
    onboardingPort,
    credentials.validateTeam.bind(credentials),
    Date.now,
  );
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
  );
  const collections = new DeviceCollection(
    db,
    devices,
    Date.now,
    collectionCms,
    nativeCollectionSession,
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
  const clientInstaller = new ClientInstallations({
    db,
    release: new LocalClientRelease(process.env),
    jobs,
    storage,
    devices,
    tickets,
    now: Date.now,
    ensureSigningReady: async (owner) => {
      if (!pipeline.kickoff) throw new Failure('NATIVE_PIPELINE_REQUIRED', 503);
      await signingReadiness.ensure(owner);
    },
  });
  const lifecycle = new RequestLifecycle(accounts, storage, artifacts);
  const queries = new RuntimeQueries(db, Date.now);
  const sharing = new AppleSharing(db, Date.now);
  const nativeAssets = new FeatherSigningAssets(db, {
    api: readyApi,
    vault,
    material: new OpenSslSigningMaterial(process.env.ISIGN_OPENSSL ?? '/usr/bin/openssl'),
    verify: pipeline.cmsVerifier ?? denyControlProfile,
    now: Date.now,
  });
  const nativeApplication = new NativeApplication({
    auth: nativeSessions,
    queries,
    sharing,
    collections,
    devices,
    actions: deviceActions,
    catalogs,
    catalog: new FeatherCatalog(db, catalogs, { now: Date.now }),
    assets: nativeAssets,
    admin: kernel.admin,
    connectApple: connectApple.run.bind(connectApple),
    disconnectApple: connections.disconnectFor.bind(connections),
    deleteAccount: lifecycle.deleteAccountFor.bind(lifecycle),
    bootstrap,
  });
  const diagnostics =
    process.env.ISIGN_PROFILE_DIAGNOSTICS === '1'
      ? new ProfileDiagnostics(db, Date.now, '/state/isign/profile-diagnostics')
      : undefined;
  const deviceCallback = new ReceiveDeviceCallback(collections, diagnostics);
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
    receiveDeviceCallback: deviceCallback.run.bind(deviceCallback),
    runnerAuthorization,
    backgroundTasks: [
      { name: 'feather', intervalMs: 60000, run: () => nativeAssets.maintain() },
      {
        name: 'queue',
        intervalMs: 5000,
        run: () =>
          jobs
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
          storage.objects
            .recover()
            .then(() => storage.cleanup())
            .then(() => artifacts.cleanup())
            .then(() => jobs.recoverLeases(pipeline.retireExecutor, retireLaunch))
            .then(() => dispatcher.dispatch())
            .then(() => kernel.secretDeletionWorker.runOne())
            .then(() => cleanupHistory(db, Date.now())),
      },
    ],
    close: db.close.bind(db),
    sessions: {
      session: sessions.session.bind(sessions),
      authorizeWrite: sessions.authorizeWrite.bind(sessions),
      fresh: sessions.fresh.bind(sessions),
      logout: sessions.logout.bind(sessions),
    },
    deviceActions: { selectDevice: deviceActions.selectDevice.bind(deviceActions) },
    connections: { disconnect: connections.disconnect.bind(connections) },
    queries,
    catalogs,
    artifacts: { open: artifacts.open.bind(artifacts) },
    tickets,
    bootstrap,
    auth: {
      rate: kernel.auth.rate.bind(kernel.auth),
      registrationOptions: kernel.auth.registrationOptions.bind(kernel.auth),
      register: kernel.auth.register.bind(kernel.auth),
      authenticationOptions: kernel.auth.authenticationOptions.bind(kernel.auth),
      authenticate: kernel.auth.authenticate.bind(kernel.auth),
      addOptions: kernel.auth.addOptions.bind(kernel.auth),
    },
    devices,
    collections,
    sharing,
    readiness: readiness.check.bind(readiness),
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
