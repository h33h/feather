import { createRuntime, type Runtime } from './composition';
import { startBackgroundTasks } from './background-tasks';
import { Failure } from '../packages/core/src/shared/index';
export { origin } from './composition';
const root = globalThis as typeof globalThis & {
  isignRuntime?: Promise<Runtime>;
  isignBackgroundTasks?: ReturnType<typeof startBackgroundTasks>;
  isignStopping?: boolean;
  isignShutdown?: Promise<void>;
};
export function shutdownRuntime() {
  root.isignStopping = true;
  return (root.isignShutdown ??= (async () => {
    await root.isignBackgroundTasks?.stop();
    const app = await root.isignRuntime?.catch(() => undefined);
    await app?.close();
  })());
}
Object.defineProperty(process, Symbol.for('isign.runtime.shutdown'), {
  configurable: true,
  value: shutdownRuntime,
});
export async function runtime() {
  if (root.isignStopping) throw new Failure('SERVICE_SHUTTING_DOWN', 503);
  const initializing = (root.isignRuntime ??= createRuntime());
  let app: Runtime;
  try {
    app = await initializing;
  } catch (error) {
    if (root.isignRuntime === initializing) delete root.isignRuntime;
    throw error;
  }
  if (root.isignStopping) throw new Failure('SERVICE_SHUTTING_DOWN', 503);
  if (!root.isignBackgroundTasks && app.backgroundTasks) {
    root.isignBackgroundTasks = startBackgroundTasks(app.backgroundTasks);
    for (const signal of ['SIGTERM', 'SIGINT'] as const)
      process.once(signal, () => {
        void root.isignBackgroundTasks?.stop();
      });
  }
  return app;
}
