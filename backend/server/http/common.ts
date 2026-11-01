import { NextRequest, NextResponse } from 'next/server';
import { Failure } from '../../packages/core/src/shared/index';
export async function body(request: NextRequest, maxBytes = 8 * 1024 ** 2) {
  if (!request.body) return {};
  const reader = request.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new Failure('REQUEST_TOO_LARGE', 413);
      parts.push(value);
    }
    return JSON.parse(Buffer.concat(parts).toString('utf8')) as Record<string, unknown>;
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error instanceof Failure) throw error;
    throw new Failure('INVALID_REQUEST');
  } finally {
    reader.releaseLock();
  }
}
export function response(value: unknown, status = 200) {
  return NextResponse.json(value, {
    status,
    headers: {
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
