import { Readable } from 'node:stream';
import { Failure } from '../shared/index';
/** HTTP body owns its deadline even if the underlying FD reached EOF/prefetched.
 * No web queue is retained after expiry; client copies received earlier are outside
 * server retention. The zero water mark avoids fetching while the consumer pauses.
 */
export function guardedDownload(options: {
  source: Readable;
  close: () => Promise<void>;
  check: () => Promise<unknown>;
  expiresAt: number;
  signal?: AbortSignal;
  now?: () => number;
}) {
  const { source, close, check, expiresAt, signal } = options,
    now = options.now ?? Date.now;
  const iterator = source[Symbol.asyncIterator]();
  let ended = false,
    timer: ReturnType<typeof setTimeout> | undefined;
  let controller: ReadableStreamDefaultController<Uint8Array>;
  const cleanup = () => {
    if (timer) clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
    source.removeListener('error', abort);
    source.destroy();
    void close().catch(() => {});
  };
  const abort = (error: unknown) => {
    if (ended) return;
    ended = true;
    controller.error(error);
    cleanup();
  };
  const cancel = () => abort(new Failure('DOWNLOAD_INTERRUPTED', 410));
  return new ReadableStream<Uint8Array>(
    {
      start(value) {
        controller = value;
        source.on('error', abort);
        signal?.addEventListener('abort', cancel, { once: true });
        timer = setTimeout(
          () => abort(new Failure('ARTIFACT_EXPIRED', 410)),
          Math.max(0, expiresAt - now()),
        );
        timer.unref();
        if (signal?.aborted) cancel();
      },
      async pull(value) {
        try {
          if (ended) return;
          if (now() >= expiresAt) throw new Failure('ARTIFACT_EXPIRED', 410);
          await check();
          const next = await iterator.next();
          if (ended) return;
          if (now() >= expiresAt) throw new Failure('ARTIFACT_EXPIRED', 410);
          await check();
          if (ended) return;
          if (next.done) {
            ended = true;
            value.close();
            cleanup();
          } else value.enqueue(next.value as Uint8Array);
        } catch (error) {
          abort(error);
        }
      },
      cancel() {
        if (!ended) {
          ended = true;
          cleanup();
        }
      },
    },
    { highWaterMark: 0 },
  );
}
