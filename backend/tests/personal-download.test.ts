import { Readable } from 'node:stream';
import { expect, test, vi } from 'vitest';
import { guardedDownload } from '../packages/core/src/library/guarded-download';
test('expiry rejects a paused HTTP body and closes its descriptor without another pull', async () => {
  vi.useFakeTimers();
  vi.setSystemTime(1000);
  const source = new Readable({ read() {} }),
    close = vi.fn(async () => {});
  source.push(Buffer.from('synthetic'));
  try {
    const body = guardedDownload({ source, close, check: async () => {}, expiresAt: 2000 });
    const reader = body.getReader();
    expect((await reader.read()).value?.length).toBe(9);
    await vi.advanceTimersByTimeAsync(1000);
    await expect(reader.read()).rejects.toThrow('ARTIFACT_EXPIRED');
    expect(source.destroyed).toBe(true);
    expect(close).toHaveBeenCalledTimes(1);
  } finally {
    vi.useRealTimers();
  }
});
test('unconsumed body cannot release prefetched bytes after expiration', async () => {
  vi.useFakeTimers();
  vi.setSystemTime(1000);
  const source = Readable.from([Buffer.from('synthetic')]),
    close = vi.fn(async () => {});
  try {
    const body = guardedDownload({ source, close, check: async () => {}, expiresAt: 2000 });
    await vi.advanceTimersByTimeAsync(1000);
    await expect(body.getReader().read()).rejects.toThrow('ARTIFACT_EXPIRED');
    expect(close).toHaveBeenCalledTimes(1);
  } finally {
    vi.useRealTimers();
  }
});
