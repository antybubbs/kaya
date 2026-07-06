(function () {
  const liveToggle = document.querySelector("[data-dns-live-toggle]");
  const liveStorageKey = "kaya.dns.queryLog.live";
  const liveIntervalMs = 10000;
  let liveTimer = null;

  function onQueryLogPage() {
    return new URLSearchParams(window.location.search).get("tab") === "query-log";
  }

  function setLiveMode(enabled) {
    if (!liveToggle) return;
    liveToggle.checked = enabled;
    localStorage.setItem(liveStorageKey, enabled ? "1" : "0");
    if (liveTimer) {
      window.clearInterval(liveTimer);
      liveTimer = null;
    }
    if (enabled && onQueryLogPage()) {
      liveTimer = window.setInterval(() => {
        if (!document.hidden) {
          window.location.reload();
        }
      }, liveIntervalMs);
    }
  }

  if (liveToggle) {
    setLiveMode(localStorage.getItem(liveStorageKey) === "1");
    liveToggle.addEventListener("change", () => setLiveMode(liveToggle.checked));
  }

  document.querySelectorAll("[data-dns-domain-detail]").forEach((button) => {
    button.addEventListener("click", () => {
      const row = button.closest("tr");
      const detailRow = row ? row.nextElementSibling : null;
      if (!detailRow || !detailRow.classList.contains("dns-domain-detail-row")) return;
      const expanded = !detailRow.hidden;
      detailRow.hidden = expanded;
      button.setAttribute("aria-expanded", expanded ? "false" : "true");
    });
  });
})();
