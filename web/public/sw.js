// Retire existing iSign web-app registrations after upgrading to the native installer.
self.addEventListener('install', (event) => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      for (const name of await caches.keys())
        if (name.startsWith('isign-offline-')) await caches.delete(name);
      await self.clients.claim();
      await self.registration.unregister();
    })(),
  );
});
