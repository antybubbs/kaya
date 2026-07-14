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
  let dashboardTimer = null;
  let dashboardRefreshInFlight = false;

  function connectionStatusElement() {
    return document.querySelector("[data-dns-connection-status]");
  }

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
    const connectionStatus = connectionStatusElement();
    if (!connectionStatus || document.hidden) return;
    try {
      const providerId = insightRoot()?.dataset.providerId;
      const statusUrl = new URL("/networking/dns-manager/connection-status", window.location.origin);
      if (providerId) statusUrl.searchParams.set("provider_id", providerId);
      const response = await fetch(statusUrl.toString(), { credentials: "same-origin", headers: { Accept: "application/json" } });
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
  if (connectionStatusElement()) {
    refreshConnectionStatus();
    window.setInterval(refreshConnectionStatus, 30000);
  }

  let insightRequestInFlight = false;

  function insightRoot() {
    return document.querySelector("[data-dns-insights-root]");
  }

  function showInsightMessage(message, ok) {
    const box = insightRoot()?.querySelector("[data-dns-insights-message]");
    if (!box) return;
    box.hidden = false;
    box.textContent = message;
    box.classList.toggle("success", Boolean(ok));
  }

  async function replaceInsights(url, updateHistory) {
    const response = await fetch(url.toString(), { credentials: "same-origin", headers: { Accept: "text/html" } });
    if (!response.ok) throw new Error(`Insights refresh failed: ${response.status}`);
    const doc = new DOMParser().parseFromString(await response.text(), "text/html");
    const next = doc.querySelector("[data-dns-insights-root]");
    const current = insightRoot();
    if (!next || !current) throw new Error("Insights response was incomplete.");
    current.replaceWith(document.importNode(next, true));
    const nextProviderState = doc.querySelector(".dns-provider-state");
    const currentProviderState = document.querySelector(".dns-provider-state");
    if (nextProviderState && currentProviderState) currentProviderState.replaceWith(document.importNode(nextProviderState, true));
    if (updateHistory) window.history.replaceState({}, "", url.toString());
  }

  async function analyseInsights(button) {
    const root = insightRoot();
    if (!root || insightRequestInFlight) return;
    insightRequestInFlight = true;
    document.querySelectorAll("[data-dns-analyse-now]").forEach((item) => { item.disabled = true; item.textContent = "Analysing..."; });
    const data = new FormData();
    data.set("provider_id", root.dataset.providerId || "");
    data.set("csrf_token", root.dataset.csrfToken || "");
    try {
      const response = await fetch("/networking/dns-manager/insights/analyse", { method: "POST", credentials: "same-origin", body: data });
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(result.message || "Unable to update DNS insights.");
      await replaceInsights(new URL(window.location.href), false);
      showInsightMessage(result.message || "DNS insights updated.", true);
    } catch (error) {
      showInsightMessage(error.message, false);
    } finally {
      insightRequestInFlight = false;
      document.querySelectorAll("[data-dns-analyse-now]").forEach((item) => { item.disabled = false; item.textContent = item === button ? "Analyse now" : item.textContent.replace("Analysing...", "Refresh now"); });
    }
  }

  async function acknowledgeInsight(insightId) {
    const root = insightRoot();
    if (!root || insightRequestInFlight) return;
    insightRequestInFlight = true;
    const data = new FormData();
    data.set("csrf_token", root.dataset.csrfToken || "");
    try {
      const response = await fetch(`/networking/dns-manager/insights/${encodeURIComponent(insightId)}/acknowledge`, { method: "POST", credentials: "same-origin", body: data });
      const result = await response.json();
      if (!response.ok || !result.ok) throw new Error(result.message || "Unable to acknowledge insight.");
      await replaceInsights(new URL(window.location.href), false);
      showInsightMessage(result.message, true);
    } catch (error) {
      showInsightMessage(error.message, false);
    } finally {
      insightRequestInFlight = false;
    }
  }

  document.addEventListener("click", (event) => {
    const analyseButton = event.target.closest("[data-dns-analyse-now]");
    if (analyseButton) {
      event.preventDefault();
      analyseInsights(analyseButton);
      return;
    }
    const acknowledgeButton = event.target.closest("[data-dns-acknowledge]");
    if (acknowledgeButton) {
      event.preventDefault();
      acknowledgeInsight(acknowledgeButton.dataset.dnsAcknowledge);
    }
  });

  document.addEventListener("change", async (event) => {
    const form = event.target.closest("[data-dns-insight-filters]");
    if (!form || insightRequestInFlight) return;
    insightRequestInFlight = true;
    const url = new URL(form.action, window.location.origin);
    new FormData(form).forEach((value, key) => url.searchParams.set(key, value));
    try {
      await replaceInsights(url, true);
    } catch (error) {
      showInsightMessage(error.message, false);
    } finally {
      insightRequestInFlight = false;
    }
  });

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

  document.addEventListener("toggle", function (event) {
    const details = event.target;

    if (
        !(details instanceof HTMLDetailsElement) ||
        !details.classList.contains("dns-domain-menu") ||
        !details.open
    ) {
        return;
    }

    const summary = details.querySelector("summary");
    const panel = details.querySelector(".dns-domain-menu-panel");

    if (!summary || !panel) {
        return;
    }

    // Close any other open domain menus.
  document.querySelectorAll(".dns-domain-menu[open]").forEach((item) => {
        if (item !== details) {
            item.removeAttribute("open");
        }
    });

    const summaryRect = summary.getBoundingClientRect();

    // Measure the popup after it becomes visible.
    requestAnimationFrame(() => {
        const panelRect = panel.getBoundingClientRect();
        const margin = 12;

        let left = summaryRect.left;
        let top = summaryRect.bottom + 8;

        // Keep popup inside the right edge of the viewport.
        if (left + panelRect.width > window.innerWidth - margin) {
            left = window.innerWidth - panelRect.width - margin;
        }

        // If there is not enough room below, open it above.
        if (top + panelRect.height > window.innerHeight - margin) {
            top = summaryRect.top - panelRect.height - 8;
        }

        // Keep popup inside the viewport.
        left = Math.max(margin, left);
        top = Math.max(margin, top);

        details.style.setProperty("--dns-popup-left", `${left}px`);
        details.style.setProperty("--dns-popup-top", `${top}px`);
    });
  }, true);

  document.addEventListener("click", function (event) {
    document.querySelectorAll(".dns-domain-menu[open]").forEach((details) => {
        if (!details.contains(event.target)) {
            details.removeAttribute("open");
        }
    });
  });
})();
