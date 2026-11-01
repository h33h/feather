import { NextResponse } from 'next/server';
import { origin } from '../runtime';
import { Failure } from '../../packages/core/src/shared/index';
import type { PublicContext } from './context';
export async function handleCallback(context: PublicContext) {
  const { request, target, app } = context;
  if (target === 'devices/callback' && request.method === 'POST') {
    if ((!app.collections && !app.devices) || new URL(origin).protocol !== 'https:')
      throw new Failure('CMS_VERIFIER_UNAVAILABLE', 503);
    const cap = request.nextUrl.searchParams.get('challenge') ?? '';
    if (!/^[A-Za-z0-9_-]{43}$/.test(cap) || !request.body)
      throw new Failure('INVALID_DEVICE_CALLBACK');
    const reader = request.body.getReader();
    const parts: Buffer[] = [];
    let count = 0;
    try {
      for (;;) {
        const item = await reader.read();
        if (item.done) break;
        count += item.value.length;
        if (count > 65536) throw new Failure('REQUEST_TOO_LARGE', 413);
        parts.push(Buffer.from(item.value));
      }
      const packet = Buffer.concat(parts);
      await app.receiveDeviceCallback(cap, packet);
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    // UDID-only ProfileService ends by returning Safari. This flow does not
    // enroll a ProfileService identity with SCEP.
    return NextResponse.redirect(new URL('/', origin), {
      status: 301,
      headers: {
        'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  }
}
