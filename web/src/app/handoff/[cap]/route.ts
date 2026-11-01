import { NextRequest, NextResponse } from 'next/server';
import {
  publicPage,
  publicThemeScriptPolicy,
} from '../../../../../backend/server/http/public-page';
import { runtime as getRuntime, origin } from '../../../../../backend/server/runtime';
import { Failure } from '../../../../../backend/packages/core/src/shared/index';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
const headers = {
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy':
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; " +
    publicThemeScriptPolicy,
  'X-Content-Type-Options': 'nosniff',
};
// Static copy only: capability values and provider errors never enter the document.
function page(
  recovery?: {
    title: string;
    message: string;
  },
  status = 200,
) {
  const title = recovery?.title ?? 'Установить приложение на iPhone';
  const message =
    recovery?.message ??
    'Откройте эту страницу в Safari на iPhone, на который хотите установить приложение.';
  return new NextResponse(publicPage(title, message, !recovery), {
    status,
    headers: { ...headers, 'Content-Type': 'text/html; charset=utf-8' },
  });
}

async function handle(
  request: NextRequest,
  context: {
    params: Promise<{
      cap: string;
    }>;
  },
) {
  try {
    const { cap } = await context.params;
    if (request.headers.get('host') !== new URL(origin).host || !/^[A-Za-z0-9_-]{43}$/.test(cap))
      throw new Failure('NOT_FOUND', 404);
    const app = await getRuntime();
    await app.tickets.resolve(cap);
    if (request.method === 'GET') return page();
    if (request.headers.get('origin') !== origin) throw new Failure('CSRF', 403);
    if (new URL(origin).protocol !== 'https:')
      throw new Failure('HTTPS_INSTALL_ORIGIN_REQUIRED', 503);
    const ticket = cap;

    const manifest = origin + '/install/' + ticket + '/manifest.plist';
    return NextResponse.redirect(
      'itms-services://?action=download-manifest&url=' + encodeURIComponent(manifest),
      { status: 303, headers },
    );
  } catch (error) {
    const failure = error instanceof Failure ? error : new Failure('NOT_FOUND', 404);
    if (failure.code === 'CSRF')
      return page(
        {
          title: 'Откройте ссылку заново',
          message:
            'Не удалось подтвердить переход. Откройте ссылку установки в Safari и нажмите «Продолжить установку».',
        },
        failure.status,
      );
    if (failure.code === 'HTTPS_INSTALL_ORIGIN_REQUIRED')
      return page(
        {
          title: 'Установка временно недоступна',
          message:
            'Не удалось открыть защищённую ссылку установки. Вернитесь в iSign и попробуйте позже.',
        },
        failure.status,
      );
    return page(
      {
        title: 'Ссылка установки недоступна',
        message:
          'Ссылка могла истечь или доступ к приложению был отозван. Вернитесь на страницу установки iSign Client и получите новую ссылку.',
      },
      failure.status,
    );
  }
}
export const GET = handle;
export const POST = handle;
