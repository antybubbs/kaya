(function () {
  const root = document.querySelector("[data-network-traffic-admin]");
  if (!root) return;
  const csrf = root.dataset.csrf || "";
  const escape = (value) => { const node = document.createElement("span"); node.textContent = value == null ? "" : String(value); return node.innerHTML; };
  const request = async (url, options = {}) => {
    const response = await fetch(url, { ...options, credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...(options.method && options.method !== "GET" ? { "X-CSRF-Token": csrf } : {}), ...(options.headers || {}) } });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || "The request could not be completed.");
    return payload;
  };
  const setText = (selector, value) => { const node = root.querySelector(selector); if (node) node.textContent = value == null || value === "" ? "No data" : String(value); };
  const render = (payload) => {
    setText("[data-admin-status-label]", payload.status_label);
    setText("[data-admin-status-reason]", payload.status_reason);
    setText("[data-admin-status]", payload.status_label);
    setText("[data-admin-heartbeat]", payload.heartbeat_at || "No heartbeat recorded");
    setText("[data-admin-last-packet]", payload.last_packet_at || "No packet recorded");
    setText("[data-admin-listener]", payload.listener_state);
    const checkbox = root.querySelector("[data-admin-enabled]"); if (checkbox) checkbox.checked = !!payload.global_enabled;
    Object.entries(payload.runtime || {}).forEach(([key, value]) => setText(`[data-admin-runtime="${CSS.escape(key)}"]`, key === "max_packets_per_second" ? `${value}/s` : value));
    Object.entries(payload.counters || {}).forEach(([key, value]) => setText(`[data-admin-counter="${CSS.escape(key)}"]`, value));
    setText("[data-admin-source-summary]", `${payload.sources.configured} configured flow source(s), ${payload.sources.enabled} enabled.`);
    const sourceTable = root.querySelector("[data-admin-sources]");
    if (sourceTable) sourceTable.innerHTML = (payload.sources.rows || []).length ? payload.sources.rows.map((source) => `<tr><th scope="row">${escape(source.name)}</th><td>${escape(source.provider)}</td><td>${source.enabled ? "Enabled" : "Disabled"} · ${escape(source.listener_state)}</td><td>${escape(source.port || "—")}</td><td>${escape(source.exporter_count)}</td></tr>`).join("") : '<tr><td colspan="5" class="muted">No flow sources configured.</td></tr>';
    const warnings = root.querySelector("[data-admin-warnings]");
    if (warnings) warnings.innerHTML = (payload.warnings || []).length ? payload.warnings.map((item) => `<li>${escape(item)}</li>`).join("") : '<li class="success">No known deployment warnings.</li>';
  };
  const refresh = async () => { try { render(await request("/system/site-administration/network-traffic/status")); } catch (error) { setText("[data-admin-status-reason]", error.message); } };
  root.querySelector("[data-admin-refresh]")?.addEventListener("click", refresh);
  root.querySelector("[data-admin-enabled]")?.addEventListener("change", async (event) => {
    const checkbox = event.currentTarget; checkbox.disabled = true;
    const status = root.querySelector("[data-admin-control-status]"); if (status) status.textContent = "Saving...";
    try {
      const current = await request("/networking/ip-wan-monitor/traffic/config");
      await request("/networking/ip-wan-monitor/traffic/config", { method: "PUT", body: JSON.stringify({ ...current, is_enabled: checkbox.checked }) });
      if (status) status.textContent = "Saved. Collector workers will apply the setting during their refresh cycle.";
      await refresh();
    } catch (error) { checkbox.checked = !checkbox.checked; if (status) status.textContent = error.message; }
    checkbox.disabled = false;
  });
  const discoveryRoot = document.querySelector("[data-discovery-admin]");
  if (discoveryRoot) {
    const form = discoveryRoot.querySelector("[data-discovery-config-form]");
    const status = discoveryRoot.querySelector("[data-discovery-config-status]");
    const loadDiscoveryConfig = async () => {
      const response = await request("/api/network-discovery/configuration");
      Object.entries(response).forEach(([key, value]) => { const field = form?.elements.namedItem(key); if (field) field.type === "checkbox" ? field.checked = !!value : field.value = value; });
    };
    loadDiscoveryConfig().catch(error => { if (status) status.textContent = error.message; });
    form?.addEventListener("submit", async event => { event.preventDefault(); const button = form.querySelector("button[type=submit]"); if (button) button.disabled = true; if (status) status.textContent = "Saving…"; try { const body = Object.fromEntries(new FormData(form).entries()); body.is_enabled = form.elements.is_enabled.checked; ["detailed_retention_hours", "summary_retention_days", "max_detail_rows", "max_summary_rows"].forEach(key => { body[key] = Number(body[key]); }); await request("/api/network-discovery/configuration", { method: "PUT", body: JSON.stringify(body) }); if (status) status.textContent = "Discovery settings saved."; } catch (error) { if (status) status.textContent = error.message; } finally { if (button) button.disabled = false; } });
  }
  window.setInterval(refresh, 15000);
})();
