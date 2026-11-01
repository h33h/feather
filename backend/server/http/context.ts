import type { NextRequest } from 'next/server';
import type { HttpApplication } from './application';
import type { InstallationHistory } from '../../packages/core/src/library/installation-history';
export type PublicContext = {
  request: NextRequest;
  target: string;
  app: HttpApplication;
  raw: string;
  csrf: string;
};
export type AuthenticatedContext = PublicContext & {
  owner: string;
  session: Awaited<ReturnType<PublicContext['app']['service']['session']>>;
  history: Pick<InstallationHistory, 'list'>;
  uploadAllowed: () => Promise<boolean>;
  requireUpload: () => Promise<void>;
};
