const CACHE_VERSION = "kaya-static-v2";
const scopePath = new URL(self.registration.scope).pathname.replace(/\/$/, "");
const staticPath = `${scopePath}/static`;
const OFFLINE_URL = `${staticPath}/offline.html`;
const PRECACHE_URLS = [
  OFFLINE_URL,
  `${staticPath}/brand/kaya-favicon-192.png`,
  `${staticPath}/brand/kaya-favicon-512.png`,
  `${staticPath}/brand/kaya-apple-touch-icon-180.png`,
  `${staticPath}/css/sidebar.css`,
  `${staticPath}/images/sidebar/sidebar-infrastructure-bg.webp`
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_VERSION).then((cache) => cache.addAll(PRECACHE_URLS)));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE_VERSION).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("message", (event) => {
  if (event.data?.type === "SKIP_WAITING") self.skipWaiting();
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  if (request.mode === "navigate") {
    event.respondWith(fetch(request).catch(() => caches.match(OFFLINE_URL)));
    return;
  }

  if (!url.pathname.startsWith(`${staticPath}/`)) return;
  event.respondWith(
    caches.match(request).then((cached) => cached || fetch(request).then((response) => {
      if (!response.ok || response.type !== "basic") return response;
      const copy = response.clone();
      caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy));
      return response;
    }))
  );
});
