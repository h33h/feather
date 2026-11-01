import type { NativeSessions } from '../../packages/core/src/auth/native-sessions';
import type { NativeApplication } from '../../packages/core/src/application/native-application';
import type { Runtime } from '../composition';

/** HTTP receives only public application operations, never storage or database capabilities. */
type Operations<T> = Pick<
  T,
  {
    [K in keyof T]: T[K] extends (...args: never[]) => unknown ? K : never;
  }[keyof T]
>;
type ServiceNames =
  | 'clientInstaller'
  | 'queries'
  | 'catalogs'
  | 'auth'
  | 'devices'
  | 'collections'
  | 'sharing'
  | 'sessions'
  | 'deviceActions'
  | 'connections';
export type HttpApplication = {
  [K in ServiceNames]: Operations<Runtime[K]>;
} & Pick<
  Runtime,
  'connectApple' | 'receiveDeviceCallback' | 'bootstrap' | 'readiness' | 'capabilities'
> & {
    nativeApplication: Pick<NativeApplication, 'view' | 'command'>;
    nativeSessions: Pick<
      NativeSessions,
      'start' | 'complete' | 'exchange' | 'refresh' | 'authorize' | 'requireFresh' | 'logout'
    >;
    runnerAuthorization?: Operations<NonNullable<Runtime['runnerAuthorization']>>;
  };
