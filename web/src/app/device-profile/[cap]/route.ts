import { NextRequest, NextResponse } from 'next/server';
import {
  publicPage,
  publicThemeScriptPolicy,
} from '../../../../../backend/server/http/public-page';
import { runtime as getRuntime, origin } from '../../../../../backend/server/runtime';
import { profileServiceXml } from '../../../../../backend/packages/core/src/devices/onboarding';
import { Failure } from '../../../../../backend/packages/core/src/shared/index';
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export async function GET(
  request: NextRequest,
  context: {
    params: Promise<{
      cap: string;
    }>;
  },
) {
  try {
    const { cap } = await context.params;
    if (request.headers.get('host') !== new URL(origin).host)
      throw new Failure('INVALID_HOST', 403);
    const app = await getRuntime(),
      profile = await app.collections.redeemProfile(cap);
    return new NextResponse(profileServiceXml(origin, profile.challenge), {
      headers: {
        'Content-Type': 'application/x-apple-aspen-config',
        'Content-Disposition': 'attachment; filename="isign-device.mobileconfig"',
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch {
    return new NextResponse(
      publicPage(
        'Профиль недоступен',
        'Ссылка истекла или уже использована. Вернитесь в настройки iSign и скачайте новый профиль.',
      ),
      {
        status: 410,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
          'Referrer-Policy': 'no-referrer',
          'X-Content-Type-Options': 'nosniff',
          'Content-Security-Policy':
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; " +
            publicThemeScriptPolicy,
        },
      },
    );
  }
}
