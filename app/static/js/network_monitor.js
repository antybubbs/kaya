(function () {
  const tabs = document.querySelector(".detail-tabs");
  const panels = ["overview", "performance", "history", "events", "settings"].map((id) => document.getElementById(id)).filter(Boolean);
  if (tabs && panels.length) {
    const showTab = () => {
      const selected = panels.some((panel) => `#${panel.id}` === window.location.hash) ? window.location.hash.slice(1) : "overview";
      panels.forEach((panel) => { panel.hidden = panel.id !== selected; });
      tabs.querySelectorAll("a").forEach((link) => link.classList.toggle("active", link.hash === `#${selected}`));
    };
    window.addEventListener("hashchange", showTab);
    showTab();
  }
  const container = document.querySelector("[data-monitor-content]");
  if (!container) {
    return;
  }

  let loading = false;
  let collectionRunning = false;
  let refreshTimer = null;
  const refreshSelect = document.querySelector("[data-monitor-refresh-rate]");
  const storageKey = "kaya.ipWanMonitor.collectionRate";
  const clientKey = "kaya.ipWanMonitor.collectionClient";
  const clientId = window.sessionStorage.getItem(clientKey) || (window.crypto?.randomUUID?.() || `${Date.now()}-${Math.random()}`);
  window.sessionStorage.setItem(clientKey, clientId);

  async function refreshCards() {
    if (loading) {
      return;
    }
    loading = true;
    try {
      const response = await fetch("/networking/ip-wan-monitor/cards", {
        headers: { "X-Requested-With": "fetch" },
        cache: "no-store",
      });
      if (response.ok) {
        container.innerHTML = await response.text();
      }
    } finally {
      loading = false;
    }
  }

  function collectionPayload(mode) {
    const payload = new FormData();
    payload.set("mode", mode);
    payload.set("client_id", clientId);
    payload.set("csrf_token", refreshSelect?.dataset.monitorCsrf || "");
    return payload;
  }

  async function collectAndRefresh(mode) {
    if (collectionRunning || document.hidden) {
      return;
    }
    collectionRunning = true;
    refreshSelect?.classList.add("is-live");
    try {
      const response = await fetch("/networking/ip-wan-monitor/collect", {
        method: "POST",
        body: collectionPayload(mode),
        cache: "no-store",
      });
      if (response.ok) {
        await refreshCards();
      }
    } finally {
      collectionRunning = false;
      refreshSelect?.classList.remove("is-live");
    }
  }

  function releaseOverride() {
    if (!refreshSelect) return;
    navigator.sendBeacon("/networking/ip-wan-monitor/collect", collectionPayload("default"));
  }

  function scheduleCollection(immediate) {
    window.clearTimeout(refreshTimer);
    if (!refreshSelect || document.hidden) return;
    const mode = refreshSelect.value;
    if (mode === "default") {
      releaseOverride();
      refreshTimer = window.setTimeout(async () => {
        await refreshCards();
        scheduleCollection(false);
      }, 30000);
      return;
    }
    const delay = mode === "live" ? 250 : Number(mode);
    refreshTimer = window.setTimeout(async () => {
      await collectAndRefresh(mode);
      scheduleCollection(false);
    }, immediate ? 0 : delay);
  }

  container.addEventListener("submit", async (event) => {
    const form = event.target.closest(".monitor-refresh-form");
    if (!form) {
      return;
    }
    event.preventDefault();
    const button = form.querySelector("button");
    if (button) {
      button.disabled = true;
      button.classList.add("spinning");
    }
    try {
      const response = await fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        cache: "no-store",
      });
      if (response.ok) {
        await refreshCards();
      }
    } finally {
      if (button) {
        button.disabled = false;
        button.classList.remove("spinning");
      }
    }
  });

  if (refreshSelect) {
    const savedMode = window.sessionStorage.getItem(storageKey);
    if (["default", "live", "5000", "10000", "60000", "300000"].includes(savedMode)) {
      refreshSelect.value = savedMode;
    }
    refreshSelect.addEventListener("change", () => {
      window.sessionStorage.setItem(storageKey, refreshSelect.value);
      scheduleCollection(true);
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        window.clearTimeout(refreshTimer);
        releaseOverride();
      } else {
        scheduleCollection(true);
      }
    });
    window.addEventListener("pagehide", releaseOverride);
    scheduleCollection(refreshSelect.value !== "default");
  } else {
    window.setInterval(refreshCards, 30000);
  }
})();
