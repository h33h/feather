'use client';
import { useEffect } from 'react';
/** Retire the web app without deleting caches belonging to other applications. */
export function RetireWebApp() {
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;
    void navigator.serviceWorker
      .getRegistrations()
      .then(async (registrations) => {
        for (const registration of registrations) {
          const worker = registration.active ?? registration.waiting ?? registration.installing;
          if (
            worker &&
            new URL(worker.scriptURL).origin === location.origin &&
            new URL(worker.scriptURL).pathname === '/sw.js'
          )
            await registration.unregister();
        }
        if ('caches' in window)
          for (const name of await caches.keys())
            if (name.startsWith('isign-offline-')) await caches.delete(name);
      })
      .catch(() => {});
  }, []);
  return null;
}
