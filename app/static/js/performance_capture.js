(() => {
  const storageKey = "kaya.performance.capture";
  const saved = (() => {
    try { return JSON.parse(sessionStorage.getItem(storageKey) || "null"); } catch (_) { return null; }
  })();
  if (!saved || !saved.captureId || Date.now() >= Number(saved.expiresAt || 0)) {
    sessionStorage.removeItem(storageKey);
    return;
  }
  const csrf = document.body?.dataset.csrfToken || "";
  const route = () => window.location.pathname.replace(/\/[0-9]+(?=\/|$)/g, "/{id}");
  const events = [];
  let sent = false;
  const navigation = performance.getEntriesByType("navigation")[0];
  if (navigation) events.push({name: "navigation", route: route(), duration_ms: navigation.duration, dom_content_loaded_ms: navigation.domContentLoadedEventEnd, load_ms: navigation.loadEventEnd});
  performance.getEntriesByType("resource").filter(entry => entry.name.includes("/api/")).slice(0, 80).forEach(entry => {
    try { events.push({name: "api", route: new URL(entry.name, window.location.origin).pathname, duration_ms: entry.duration}); } catch (_) {}
  });
  let errorCount = 0;
  window.addEventListener("error", () => { errorCount += 1; });
  const send = () => {
    if (sent) return;
    sent = true;
    if (errorCount) events.push({name: "browser_error", route: route(), error_count: errorCount});
    if (!events.length) return;
    const body = JSON.stringify({csrf_token: csrf, events});
    const blob = new Blob([body], {type: "application/json"});
    if (navigator.sendBeacon && navigator.sendBeacon("/api/system/about/performance/capture/browser", blob)) return;
    fetch("/api/system/about/performance/capture/browser", {method: "POST", headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body, keepalive: true}).catch(() => {});
  };
  window.setTimeout(send, 1000);
  window.addEventListener("pagehide", send, {once: true});
})();
