import { Failure } from '../shared/index';
import { fetchSafe, validateUrl, type Options } from './safe-fetch';
export function rasterType(bytes: Buffer) {
  if (bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])))
    return 'image/png';
  if (bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return 'image/jpeg';
  if (['GIF87a', 'GIF89a'].includes(bytes.subarray(0, 6).toString('ascii'))) return 'image/gif';
  if (
    bytes.subarray(0, 4).toString('ascii') === 'RIFF' &&
    bytes.subarray(8, 12).toString('ascii') === 'WEBP'
  )
    return 'image/webp';
  throw new Failure('ICON_UNSUPPORTED', 415);
}
type Icon = {
  bytes: Buffer;
  type: string;
};
export class CatalogIcons {
  private cache = new Map<
    string,
    {
      icon: Icon;
      until: number;
    }
  >();
  private inflight = new Map<string, Promise<Icon>>();
  private bytes = 0;
  private active = 0;
  private waiting: (() => void)[] = [];
  private acquire() {
    if (this.active < this.concurrency) {
      this.active++;
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiting = this.waiting.filter((item) => item !== start);
        reject(new Failure('ICON_BUSY', 429));
      }, 5000);
      timer.unref();
      const start = () => {
        clearTimeout(timer);
        resolve();
      };
      this.waiting.push(start);
    });
  }
  private release() {
    const next = this.waiting.shift();
    if (next) next();
    else this.active--;
  }
  constructor(
    private concurrency = 4,
    private maximumBytes = 8 * 1024 * 1024,
    private now = Date.now,
    private maximumQueued = 0,
  ) {}
  async get(
    value: string,
    ownerKey: string,
    download: (value: string, options: Options) => Promise<Buffer> = fetchSafe,
  ): Promise<Icon> {
    const key = ownerKey + ':' + value;
    const cached = this.cache.get(key);
    if (cached && cached.until > this.now()) return cached.icon;
    const pending = this.inflight.get(key);
    if (pending) return pending;
    if (this.inflight.size >= this.concurrency + this.maximumQueued)
      throw new Failure('ICON_BUSY', 429);
    const url = validateUrl(value),
      hosts = [url.hostname];
    if (url.hostname === 'github.com')
      hosts.push('release-assets.githubusercontent.com', 'objects.githubusercontent.com');
    const work = (async () => {
      await this.acquire();
      try {
        const bytes = await download(url.href, { hosts, maxBytes: 256 * 1024, timeoutMs: 5000 });
        const icon = { bytes, type: rasterType(bytes) };
        if (bytes.length > this.maximumBytes) throw new Failure('ICON_TOO_LARGE', 413);
        const prior = this.cache.get(key);
        if (prior) {
          this.bytes -= prior.icon.bytes.length;
          this.cache.delete(key);
        }
        while (this.cache.size >= 128 || this.bytes + bytes.length > this.maximumBytes) {
          const oldest = this.cache.keys().next().value!;
          this.bytes -= this.cache.get(oldest)!.icon.bytes.length;
          this.cache.delete(oldest);
        }
        this.cache.set(key, { icon, until: this.now() + 300000 });
        this.bytes += bytes.length;
        return icon;
      } finally {
        this.release();
      }
    })();
    this.inflight.set(key, work);
    try {
      return await work;
    } finally {
      this.inflight.delete(key);
    }
  }
}
const icons = new CatalogIcons(4, 8 * 1024 * 1024, Date.now, 24);
// Ownership/snapshot are checked by registry even for cached responses.
export const fetchIcon = (value: string, ownerKey: string) => icons.get(value, ownerKey);
