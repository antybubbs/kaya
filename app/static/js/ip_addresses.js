(function () {
  function setupVlanFilter() {
    document.querySelectorAll("[data-vlan-filter]").forEach((select) => {
      const form = select.form;
      if (!form) return;
      select.addEventListener("change", () => form.requestSubmit());
    });
  }

  function setupBulkEdit() {
    const form = document.querySelector("[data-ip-bulk-form]");
    if (!form) {
      return;
    }
    const bar = form.querySelector("[data-bulk-bar]");
    const count = form.querySelector("[data-selected-count]");
    const selectAll = form.querySelector("[data-select-all]");
    const clearButton = form.querySelector("[data-clear-selection]");
    const rowChecks = Array.from(form.querySelectorAll(".row-select"));

    function updateState() {
      const selected = rowChecks.filter((item) => item.checked);
      if (bar) {
        bar.hidden = selected.length === 0;
      }
      if (count) {
        count.textContent = String(selected.length);
      }
      if (selectAll) {
        selectAll.checked = selected.length > 0 && selected.length === rowChecks.length;
        selectAll.indeterminate = selected.length > 0 && selected.length < rowChecks.length;
      }
      rowChecks.forEach((item) => {
        item.closest("tr")?.classList.toggle("is-selected", item.checked);
      });
    }

    selectAll?.addEventListener("change", () => {
      rowChecks.forEach((item) => {
        item.checked = selectAll.checked;
      });
      updateState();
    });
    clearButton?.addEventListener("click", () => {
      rowChecks.forEach((item) => {
        item.checked = false;
      });
      updateState();
    });
    rowChecks.forEach((item) => item.addEventListener("change", updateState));
    updateState();
  }

  function setupQuickPing() {
    document.querySelectorAll("[data-ping-url]").forEach((button) => {
      const defaultLabel = button.getAttribute("title") || "Ping this IP address";
      button.addEventListener("click", async () => {
        button.disabled = true;
        button.classList.remove("quick-ping-success", "quick-ping-no-response", "quick-ping-error", "is-loading");
        button.classList.add("is-loading");
        button.title = `Checking ${button.dataset.pingAddress}...`;
        try {
          const formData = new FormData();
          formData.append("csrf_token", button.dataset.csrfToken || "");
          const response = await fetch(button.dataset.pingUrl, {
            method: "POST",
            body: formData,
            credentials: "same-origin",
            headers: { "Accept": "application/json" },
          });
          const payload = await response.json();
          if (!response.ok) {
            throw new Error(payload.detail || "Ping failed.");
          }
          if (String(payload.record_id) !== String(button.dataset.pingRecordId) || payload.target !== button.dataset.pingAddress) return;
          const timestamp = payload.checked_at ? new Date(payload.checked_at).toLocaleString() : "just now";
          const latency = payload.latency_ms == null ? "" : ` · ${payload.latency_ms} ms`;
          const reason = payload.reason || "No ICMP response was received.";
          const stateClass = payload.status === "success" ? "quick-ping-success" : payload.status === "no_response" ? "quick-ping-no-response" : "quick-ping-error";
          button.classList.add(stateClass);
          button.title = payload.status === "success" ? `${payload.target} responded successfully${latency} · ${timestamp}` : payload.status === "no_response" ? `${payload.target}: no ICMP response was received · ${timestamp}` : `${payload.target}: ${reason} · ${timestamp}`;
        } catch (error) {
          button.classList.add("quick-ping-error");
          button.title = error.message || "Ping could not be completed.";
        } finally {
          button.classList.remove("is-loading");
          button.disabled = false;
          if (!button.classList.contains("quick-ping-success") && !button.classList.contains("quick-ping-no-response") && !button.classList.contains("quick-ping-error")) button.title = defaultLabel;
        }
      });
    });
  }

  function setupDeviceTrafficToggle() {
    const input = document.querySelector("[data-device-traffic-toggle-input]");
    if (!input) return;
    const state = document.querySelector("[data-device-traffic-state]");
    const reason = document.querySelector("[data-device-traffic-reason]");
    const chip = document.querySelector("[data-device-traffic-chip]");
    const message = document.querySelector("[data-device-traffic-message]");
    const titleCase = (value) => String(value || "disabled").replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
    input.addEventListener("change", async () => {
      const enabled = input.checked;
      input.disabled = true;
      try {
        const response = await fetch(`/networking/vlan-ip-manager/${encodeURIComponent(input.dataset.recordId)}/network-traffic`, {
          method: "PUT",
          credentials: "same-origin",
          headers: { "Accept": "application/json", "Content-Type": "application/json", "X-CSRF-Token": input.dataset.csrfToken || "" },
          body: JSON.stringify({ enabled }),
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.detail || "Network Traffic setting could not be saved.");
        const label = titleCase(payload.status);
        if (state) state.textContent = label;
        if (reason) reason.textContent = payload.reason || "";
        if (chip) chip.textContent = `Network Traffic ${label}`;
        if (message) message.textContent = payload.enabled ? "Loading recent persisted usage..." : "Disabled — enable Network Traffic for this record to collect usage.";
        window.location.reload();
      } catch (error) {
        input.checked = !enabled;
        input.disabled = false;
        if (reason) reason.textContent = error.message || "Network Traffic setting could not be saved.";
      }
    });
  }

  function setupDeviceTrafficReport() {
    const card = document.querySelector("[data-device-traffic-card]");
    if (!card || !card.querySelector("[data-device-spark]")) return;
    const esc = (value) => { const node = document.createElement("span"); node.textContent = value == null ? "" : String(value); return node.innerHTML; };
    const bytes = (value) => { let n = Number(value) || 0; const units = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; } return `${n.toFixed(n >= 100 || i === 0 ? 0 : 1)} ${units[i]}`; };
    fetch(`/networking/vlan-ip-manager/${encodeURIComponent(card.dataset.recordId)}/network-traffic/usage?hours=24`, { credentials: "same-origin", headers: { Accept: "application/json" } }).then(async (response) => { const payload = await response.json(); if (!response.ok) throw new Error(payload.detail || "Usage unavailable."); const rows = (payload.items || []).filter((item) => item.bucket_seconds === 300); const total = rows.reduce((sum, row) => sum + (Number(row.bytes) || 0), 0); card.querySelector("[data-device-total]").textContent = bytes(total); const latest = rows.reduce((value, row) => row.bucket_start > value ? row.bucket_start : value, ""); card.querySelector("[data-device-last]").textContent = latest ? new Date(latest).toLocaleString() : "No data"; const max = Math.max(1, ...rows.map((row) => Number(row.bytes) || 0)); const points = rows.slice(-48).map((row, index, values) => `${(index / Math.max(1, values.length - 1)) * 296 + 2},${78 - ((Number(row.bytes) || 0) / max) * 68}`).join(" "); card.querySelector("[data-device-spark]").innerHTML = points ? `<svg viewBox="0 0 300 80" role="img" aria-label="Recent device traffic bytes"><polyline points="${esc(points)}" fill="none" stroke="currentColor" stroke-width="2"></polyline></svg><small class="muted">5-minute persisted buckets · ${esc(rows.some((row) => row.data_quality !== "complete") ? "partial data" : "observed data")}</small>` : `<small class="muted">No persisted usage in the last 24 hours.</small>`; }).catch((error) => { card.querySelector("[data-device-traffic-message]").textContent = error.message; });
  }

  function setupMonitorThresholds() {
    document.querySelectorAll("[data-monitor-threshold-settings]").forEach((fieldset) => {
      const useDefaults = fieldset.querySelector("[data-monitor-threshold-defaults]");
      const source = fieldset.querySelector("[data-monitor-threshold-source]");
      const thresholdFields = Array.from(fieldset.querySelectorAll("[data-threshold-field]"));
      const interval = fieldset.closest("form")?.querySelector('[name="monitor_interval_seconds"], [name="interval_seconds"]');
      const warningLatency = fieldset.querySelector("[data-threshold-warning-latency]");
      const criticalLatency = fieldset.querySelector("[data-threshold-critical-latency]");
      const warningLoss = fieldset.querySelector("[data-threshold-warning-loss]");
      const criticalLoss = fieldset.querySelector("[data-threshold-critical-loss]");

      function updateDurations() {
        const seconds = Number(interval?.value || 300);
        const durationLabel = (value, adjectival = false) => {
          const unit = value >= 3600 && value % 3600 === 0 ? "hour" : value >= 60 && value % 60 === 0 ? "minute" : "second";
          const amount = unit === "hour" ? value / 3600 : unit === "minute" ? value / 60 : value;
          return adjectival ? `${amount}-${unit}` : `${amount} ${unit}${amount === 1 ? "" : "s"}`;
        };
        fieldset.querySelectorAll("[data-monitor-count]").forEach((input) => {
          const output = input.parentElement?.querySelector("[data-monitor-duration]");
          if (!output) return;
          const total = Number(input.value || 0) * seconds;
          output.textContent = fieldset.hasAttribute("data-readable-duration")
            ? `At the current ${durationLabel(seconds, true)} interval, this is approximately ${durationLabel(total)}.`
            : `Approximately ${total} seconds at the selected interval.`;
        });
      }

      function validatePairs() {
        criticalLatency?.setCustomValidity(
          Number(criticalLatency.value) < Number(warningLatency?.value || 0)
            ? "Critical latency must be greater than or equal to warning latency."
            : "",
        );
        criticalLoss?.setCustomValidity(
          Number(criticalLoss.value) < Number(warningLoss?.value || 0)
            ? "Critical packet loss must be greater than or equal to warning packet loss."
            : "",
        );
      }

      function updateInheritance() {
        const inherited = Boolean(useDefaults?.checked);
        thresholdFields.forEach((input) => {
          if (input.type === "checkbox") input.disabled = inherited;
          else input.readOnly = inherited;
        });
        fieldset.classList.toggle("is-inherited", inherited);
        if (source) {
          source.textContent = inherited ? "Inherited" : "Custom";
          source.classList.toggle("good", inherited);
        }
        validatePairs();
      }

      useDefaults?.addEventListener("change", updateInheritance);
      interval?.addEventListener("change", updateDurations);
      thresholdFields.forEach((input) => input.addEventListener("input", () => {
        validatePairs();
        updateDurations();
      }));
      updateInheritance();
      updateDurations();
    });
  }

  setupVlanFilter();
  setupBulkEdit();
  setupQuickPing();
  setupDeviceTrafficToggle();
  setupDeviceTrafficReport();
  setupMonitorThresholds();
})();
