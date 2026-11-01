import { Failure } from '../shared/index';
export function byteRange(value: string | null, size: number) {
  if (!value) return { start: 0, end: size - 1, partial: false };
  const match = /^bytes=(\d*)-(\d*)$/.exec(value);
  if (!match || (!match[1] && !match[2]) || size <= 0)
    throw new Failure('RANGE_NOT_SATISFIABLE', 416);
  let start: number, end: number;
  if (!match[1]) {
    const tail = Number(match[2]);
    if (!Number.isSafeInteger(tail) || tail <= 0) throw new Failure('RANGE_NOT_SATISFIABLE', 416);
    start = Math.max(0, size - tail);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] ? Number(match[2]) : size - 1;
  }
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start >= size || end < start)
    throw new Failure('RANGE_NOT_SATISFIABLE', 416);
  return { start, end: Math.min(end, size - 1), partial: true };
}
function xml(value: string) {
  return value.replace(
    /[<>&"']/g,
    (v) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[v]!,
  );
}
export function installManifest(
  origin: string,
  cap: string,
  metadata: {
    bundleId: string;
    version: string;
    title: string;
  },
) {
  const target = new URL(origin);
  if (
    target.protocol !== 'https:' ||
    target.pathname !== '/' ||
    target.username ||
    target.password ||
    target.search ||
    target.hash ||
    !/^[A-Za-z0-9_-]{43}$/.test(cap)
  )
    throw new Failure('HTTPS_INSTALL_ORIGIN_REQUIRED', 503);
  return `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${xml(target.origin + '/install/' + cap + '/application.ipa')}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${xml(metadata.bundleId)}</string><key>bundle-version</key><string>${xml(metadata.version)}</string><key>kind</key><string>software</string><key>title</key><string>${xml(metadata.title)}</string></dict></dict></array></dict></plist>`;
}
