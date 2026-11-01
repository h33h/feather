'use client';
import { useSyncExternalStore } from 'react';
const subscribe = () => () => {};
const originSnapshot = () => location.origin;
const iosSnapshot = () =>
  /iPhone|iPad|iPod/.test(navigator.userAgent) ||
  (navigator.maxTouchPoints > 1 && /Macintosh/.test(navigator.userAgent));
const serverOrigin = () => '';
const serverIOS = () => false;
/** Browser-only values stay behind a stable hydration snapshot. */
export function useBrowserContext() {
  const origin = useSyncExternalStore(subscribe, originSnapshot, serverOrigin);
  const isIOS = useSyncExternalStore(subscribe, iosSnapshot, serverIOS);
  return { origin, isIOS };
}
