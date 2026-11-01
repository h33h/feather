import type { NextRequest } from 'next/server';
import type { HttpApplication } from './application';
export type PublicContext = {
  request: NextRequest;
  target: string;
  app: HttpApplication;
  raw: string;
  csrf: string;
};
export type AuthenticatedContext = PublicContext & {
  owner: string;
  session: Awaited<ReturnType<PublicContext['app']['sessions']['session']>>;
};
