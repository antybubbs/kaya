const CACHE_VERSION = "kaya-static-v3";
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

function safeNotificationTarget(value) {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.length > 500) return "/notifications";
  try {
    const target = new URL(value, self.location.origin);
    if (target.origin !== self.location.origin || target.search || target.hash || !/^\/[A-Za-z0-9/_-]*$/.test(target.pathname)) return "/notifications";
    return target.pathname;
  } catch (_) { return "/notifications"; }
}

self.addEventListener("push", (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch (_) { payload = {}; }
  const severity = ["info", "success", "warning", "critical"].includes(payload.severity) ? payload.severity : "info";
  const title = typeof payload.title === "string" && payload.title.length <= 160 ? payload.title : "Kaya notification";
  const body = typeof payload.message === "string" && payload.message.length <= 500 ? payload.message : "Open Kaya to review this event.";
  event.waitUntil(self.registration.showNotification(title, {
    body, icon: `${staticPath}/brand/kaya-favicon-192.png`, badge: `${staticPath}/brand/kaya-favicon-192.png`,
    tag: typeof payload.notification_id === "number" ? `kaya-${payload.notification_id}` : undefined,
    data: {target: safeNotificationTarget(payload.target)}, silent: severity === "info"
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const targetPath = safeNotificationTarget(event.notification.data?.target);
  const targetUrl = new URL(`${scopePath}${targetPath}`, self.location.origin).href;
  event.waitUntil(self.clients.matchAll({type:"window", includeUncontrolled:true}).then((clients) => {
    const existing = clients.find((client) => new URL(client.url).origin === self.location.origin);
    if (existing) return existing.focus().then(() => existing.navigate(targetUrl));
    return self.clients.openWindow(targetUrl);
  }));
});
