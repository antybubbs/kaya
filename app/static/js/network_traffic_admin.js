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
      Object.entries(response).forEach(([key, value]) => { const field = form?.querySelector(`[name="${CSS.escape(key)}"]`); if (field) field.type === "checkbox" ? field.checked = !!value : field.value = value; });
    };
    loadDiscoveryConfig().catch(error => { if (status) status.textContent = error.message; });
    form?.querySelector("[data-discovery-config-submit]")?.addEventListener("click", async () => { const button = form.querySelector("[data-discovery-config-submit]"); if (button) button.disabled = true; if (status) status.textContent = "Saving…"; try { const body = { is_enabled: !!form.querySelector("[name=is_enabled]")?.checked }; ["detailed_retention_hours", "summary_retention_days", "max_detail_rows", "max_summary_rows"].forEach(key => { body[key] = Number(form.querySelector(`[name=${key}]`)?.value); }); await request("/api/network-discovery/configuration", { method: "PUT", body: JSON.stringify(body) }); if (status) status.textContent = "Discovery settings saved."; } catch (error) { if (status) status.textContent = error.message; } finally { if (button) button.disabled = false; } });
  }
  const mappingRoot = document.querySelector("[data-network-mappings-admin]");
  if (mappingRoot) {
    const form = mappingRoot.querySelector("[data-network-mapping-form]");
    const sourceSelect = mappingRoot.querySelector("[data-network-mapping-source]");
    const exporterSelect = mappingRoot.querySelector("[data-network-mapping-exporter]");
    const vlanSelect = mappingRoot.querySelector("[data-network-mapping-vlan]");
    const table = mappingRoot.querySelector("[data-network-mappings]");
    const empty = mappingRoot.querySelector("[data-network-mapping-empty]");
    const status = mappingRoot.querySelector("[data-network-mapping-status]");
    let options = { sources: [], vlans: [], mappings: [] };
    const setStatus = (message, error = false) => { if (status) { status.textContent = message || ""; status.classList.toggle("is-error", error); } };
    const sourceOptions = (selected = "") => { sourceSelect.innerHTML = '<option value="">Select a supported flow source</option>' + options.sources.map(source => `<option value="${source.id}">${escape(source.name)} (${escape(source.provider_key)})${source.is_enabled ? "" : " — disabled"}</option>`).join(""); sourceSelect.value = selected; };
    const exporterOptions = (selected = "") => { const source = options.sources.find(item => String(item.id) === String(sourceSelect.value)); const exporters = source?.exporters || []; exporterSelect.innerHTML = '<option value="">Select an exporter</option>' + exporters.map(value => `<option value="${escape(value)}">${escape(value)}</option>`).join(""); exporterSelect.value = selected; exporterSelect.disabled = !source || exporters.length === 0; };
    const vlanOptions = (selected = "") => { vlanSelect.innerHTML = '<option value="">Select a VLAN with a valid subnet</option>' + options.vlans.map(vlan => `<option value="${vlan.id}">${escape(vlan.name)} — ${escape(vlan.subnet_cidr)}</option>`).join(""); vlanSelect.value = selected; };
    const resetForm = () => { form.querySelector("[name=id]").value = ""; form.querySelector("[name=is_enabled]").checked = true; sourceOptions(); exporterOptions(); vlanOptions(); form.hidden = true; mappingRoot.querySelector("[data-network-mapping-save]").textContent = "Save mapping"; };
    const renderMappings = () => {
      const rows = options.mappings || [];
      empty.hidden = rows.length > 0;
      table.innerHTML = rows.length ? rows.map(item => `<tr><th scope="row">${escape(item.source_name)}<small class="mapping-provider">${escape(item.provider_key || "")}</small></th><td class="mono">${escape(item.exporter_identity)}</td><td>${escape(item.vlan_name)}<small class="mapping-provider">${escape(item.network_cidr || "No valid subnet")}</small></td><td>${item.is_enabled ? "Enabled" : "Disabled"}</td><td><span class="table-chip ${item.validity === "valid" ? "success" : "warning"}">${escape(item.validity)}</span>${item.validity_reason ? `<small class="mapping-provider">${escape(item.validity_reason.replaceAll("_", " "))}</small>` : ""}</td><td><div class="inline-actions"><button class="button secondary" type="button" data-mapping-edit="${item.id}">Edit</button><button class="button danger" type="button" data-mapping-delete="${item.id}">Delete</button></div></td></tr>`).join("") : '<tr><td colspan="6" class="muted">No mappings configured.</td></tr>';
    };
    const loadMappings = async () => { options = await request("/api/network-discovery/network-mappings"); sourceOptions(); exporterOptions(); vlanOptions(); renderMappings(); if (!options.sources.length) setStatus("No supported flow sources with authorised exporters are available."); else if (!options.vlans.length) setStatus("No VLAN/IP Manager networks with valid subnets are available."); else setStatus(""); };
    sourceSelect.addEventListener("change", () => exporterOptions());
    mappingRoot.querySelector("[data-network-mapping-cancel]")?.addEventListener("click", resetForm);
    mappingRoot.querySelector("[data-network-mapping-save]")?.addEventListener("click", async () => { const button = mappingRoot.querySelector("[data-network-mapping-save]"); if (!sourceSelect.value || !exporterSelect.value || !vlanSelect.value) { setStatus("Select a source, authorised exporter and VLAN network.", true); return; } button.disabled = true; setStatus("Saving..."); const id = form.querySelector("[name=id]").value; const body = { source_id: Number(sourceSelect.value), exporter_identity: exporterSelect.value, vlan_id: Number(vlanSelect.value), is_enabled: form.querySelector("[name=is_enabled]").checked }; try { await request(id ? `/api/network-discovery/network-mappings/${id}` : "/api/network-discovery/network-mappings", { method: id ? "PUT" : "POST", body: JSON.stringify(body) }); resetForm(); await loadMappings(); setStatus("Network mapping saved."); } catch (error) { setStatus(error.message, true); } finally { button.disabled = false; } });
    table.addEventListener("click", async event => { const edit = event.target.closest("[data-mapping-edit]"); const remove = event.target.closest("[data-mapping-delete]"); if (edit) { const item = options.mappings.find(row => String(row.id) === edit.dataset.mappingEdit); if (!item) return; form.hidden = false; form.querySelector("[name=id]").value = item.id; sourceOptions(item.source_id); exporterOptions(item.exporter_identity); vlanOptions(item.vlan_id); form.querySelector("[name=is_enabled]").checked = !!item.is_enabled; mappingRoot.querySelector("[data-network-mapping-save]").textContent = "Update mapping"; form.scrollIntoView({ behavior: "smooth", block: "nearest" }); } if (remove) { const item = options.mappings.find(row => String(row.id) === remove.dataset.mappingDelete); if (!item || !window.confirm(`Delete the mapping for ${item.exporter_identity} to ${item.vlan_name}? Existing discovery history is retained.`)) return; remove.disabled = true; try { await request(`/api/network-discovery/network-mappings/${item.id}`, { method: "DELETE", body: JSON.stringify({ confirmation: true }) }); await loadMappings(); setStatus("Network mapping deleted."); } catch (error) { setStatus(error.message, true); remove.disabled = false; } } });
    mappingRoot.querySelector("[data-network-mapping-add]")?.addEventListener("click", () => { form.hidden = false; form.querySelector("[name=id]").value = ""; form.querySelector("[name=is_enabled]").checked = true; form.scrollIntoView({ behavior: "smooth", block: "nearest" }); });
    const addButton = document.createElement("button"); addButton.className = "button secondary"; addButton.type = "button"; addButton.textContent = "Add mapping"; addButton.dataset.networkMappingAdd = ""; mappingRoot.querySelector(".settings-card-heading")?.append(addButton);
    addButton.addEventListener("click", () => { form.hidden = false; sourceOptions(); exporterOptions(); vlanOptions(); form.scrollIntoView({ behavior: "smooth", block: "nearest" }); });
    loadMappings().catch(error => { setStatus(error.message, true); table.innerHTML = '<tr><td colspan="6" class="muted">Mappings could not be loaded.</td></tr>'; });
  }
  window.setInterval(refresh, 15000);
})();
