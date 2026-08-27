// Bump this string any time you re-upload index.html/workouts.json/whoop.json
// so iOS knows to fetch fresh copies instead of serving the old cache.
const CACHE_NAME = 'atlas703-cache-v2';

const CORE_ASSETS = [
  './',
  './index.html',
  './plan.html',
  './workouts.json',
  './whoop.json',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

// Network-first for our own files (so you get fresh data when online),
// falling back to cache when offline (e.g. mid-workout with no signal).
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const isOwnFile = url.origin === self.location.origin;

  if (!isOwnFile) {
    // Third-party (Chart.js CDN, Google Fonts): try cache, then network.
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request).catch(() => cached))
    );
    return;
  }

  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
