(function () {
  const liveToggle = document.querySelector("[data-dns-live-toggle]");
  const queryLogPanel = document.querySelector("[data-dns-query-log]");
  const queryLogBody = document.querySelector("[data-dns-query-log-body]");
  const liveStorageKey = "kaya.dns.queryLog.live";
  const liveIntervalMs = 2000;
  let liveTimer = null;
  let refreshInFlight = false;
  const dashboardWidgets = document.querySelector("[data-dns-dashboard-widgets]");
  const dashboardRefreshSelect = document.querySelector("[data-dns-refresh-interval]");
  const dashboardRefreshKey = "kaya.dns.dashboard.refreshInterval";
  const connectionStatus = document.querySelector("[data-dns-connection-status]");
  let dashboardTimer = null;
  let dashboardRefreshInFlight = false;

  async function refreshDashboardWidgets() {
    if (!dashboardWidgets || dashboardRefreshInFlight || document.hidden) return;
    dashboardRefreshInFlight = true;
    try {
      const url = new URL(window.location.href);
      url.searchParams.set("tab", "dashboard");
      const response = await fetch(url.toString(), { credentials: "same-origin", headers: { Accept: "text/html" } });
      if (!response.ok) throw new Error(`DNS dashboard refresh failed: ${response.status}`);
      const doc = new DOMParser().parseFromString(await response.text(), "text/html");
      const nextWidgets = doc.querySelector("[data-dns-dashboard-widgets]");
      if (nextWidgets) dashboardWidgets.innerHTML = nextWidgets.innerHTML;
    } catch (error) {
      console.warn(error);
    } finally {
      dashboardRefreshInFlight = false;
    }
  }

  function setDashboardInterval(value) {
    if (!dashboardRefreshSelect) return;
    const interval = [30000, 60000, 300000].includes(Number(value)) ? Number(value) : 30000;
    dashboardRefreshSelect.value = String(interval);
    localStorage.setItem(dashboardRefreshKey, String(interval));
    if (dashboardTimer) window.clearInterval(dashboardTimer);
    dashboardTimer = window.setInterval(refreshDashboardWidgets, interval);
  }

  async function refreshConnectionStatus() {
    if (!connectionStatus || document.hidden) return;
    try {
      const response = await fetch("/networking/dns-manager/connection-status", { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error(`DNS connection check failed: ${response.status}`);
      const result = await response.json();
      connectionStatus.classList.toggle("is-connected", Boolean(result.connected));
      connectionStatus.classList.toggle("is-disconnected", !result.connected);
      connectionStatus.title = result.message || "";
      const label = connectionStatus.querySelector("[data-dns-connection-label]");
      if (label) label.textContent = result.connected ? "Connected" : "Disconnected";
    } catch (error) {
      connectionStatus.classList.remove("is-connected");
      connectionStatus.classList.add("is-disconnected");
      connectionStatus.title = error.message;
    }
  }

  if (dashboardRefreshSelect) {
    setDashboardInterval(localStorage.getItem(dashboardRefreshKey) || "30000");
    dashboardRefreshSelect.addEventListener("change", () => setDashboardInterval(dashboardRefreshSelect.value));
  }
  if (connectionStatus) {
    refreshConnectionStatus();
    window.setInterval(refreshConnectionStatus, 30000);
  }

  function onQueryLogPage() {
    return Boolean(queryLogPanel && queryLogBody);
  }

  function rowKey(row) {
    return row?.dataset?.queryKey || row?.textContent?.trim() || "";
  }

  function isEmptyRow(row) {
    return !row?.dataset?.queryKey;
  }

  function currentRowCounts() {
    const counts = new Map();
    Array.from(queryLogBody.querySelectorAll("tr")).forEach((row) => {
      const key = rowKey(row);
      if (!key) return;
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return counts;
  }

  function trimQueryRows(limit) {
    const rows = Array.from(queryLogBody.querySelectorAll("tr[data-query-key]"));
    rows.slice(limit).forEach((row) => row.remove());
  }

  async function refreshQueryLog() {
    if (!onQueryLogPage() || refreshInFlight || document.hidden) return;
    refreshInFlight = true;
    try {
      const url = new URL(window.location.href);
      url.searchParams.set("tab", "query-log");
      const response = await fetch(url.toString(), {
        credentials: "same-origin",
        headers: { Accept: "text/html" },
      });
      if (!response.ok) {
        throw new Error(`Query log refresh failed: ${response.status}`);
      }

      const html = await response.text();
      const doc = new DOMParser().parseFromString(html, "text/html");
      const nextBody = doc.querySelector("[data-dns-query-log-body]");
      if (!nextBody) return;

      const nextRows = Array.from(nextBody.querySelectorAll("tr"));
      const nextDataRows = nextRows.filter((row) => !isEmptyRow(row));
      if (!nextDataRows.length) {
        if (!queryLogBody.querySelector("tr[data-query-key]")) {
          queryLogBody.replaceChildren(...nextRows.map((row) => document.importNode(row, true)));
        }
        return;
      }

      const existingCounts = currentRowCounts();
      const seenCounts = new Map();
      const newRows = nextDataRows.filter((row) => {
        const key = rowKey(row);
        const seen = (seenCounts.get(key) || 0) + 1;
        seenCounts.set(key, seen);
        return seen > (existingCounts.get(key) || 0);
      });
      if (!newRows.length) return;

      queryLogBody.querySelectorAll("tr:not([data-query-key])").forEach((row) => row.remove());
      const fragment = document.createDocumentFragment();
      newRows.forEach((row) => {
        const imported = document.importNode(row, true);
        imported.classList.add("dns-query-row-new");
        fragment.appendChild(imported);
      });
      queryLogBody.prepend(fragment);
      trimQueryRows(200);
    } catch (error) {
      console.warn(error);
    } finally {
      refreshInFlight = false;
    }
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
      refreshQueryLog();
      liveTimer = window.setInterval(refreshQueryLog, liveIntervalMs);
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
