(function () {
  const liveToggle = document.querySelector("[data-dns-live-toggle]");
  const liveStorageKey = "kaya.dns.queryLog.live";
  const liveIntervalMs = 2000;
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
    const alertText = (document.querySelector(".alert")?.textContent || "").toLowerCase();
    if (alertText.includes("seat") || alertText.includes("429")) {
      localStorage.setItem(liveStorageKey, "0");
      liveToggle.checked = false;
      liveToggle.disabled = true;
      liveToggle.closest("label")?.setAttribute("title", "Live refresh is paused while Pi-hole API seats are exhausted.");
      return;
    }
    setLiveMode(localStorage.getItem(liveStorageKey) === "1");
    liveToggle.addEventListener("change", () => setLiveMode(liveToggle.checked));
  }

  document.addEventListener("click", (event) => {
    document.querySelectorAll(".dns-domain-menu[open]").forEach((menu) => {
      if (!menu.contains(event.target)) {
        menu.open = false;
      }
    });
  });

  document.addEventListener("toggle", (event) => {
    const activeMenu = event.target.closest(".dns-domain-menu");
    if (!activeMenu || !activeMenu.open) return;
    document.querySelectorAll(".dns-domain-menu[open]").forEach((menu) => {
      if (menu !== activeMenu) {
        menu.open = false;
      }
    });
  });
})();
