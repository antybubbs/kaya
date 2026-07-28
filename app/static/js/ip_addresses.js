(function () {
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
      const card = button.closest("[data-ping-card]");
      const message = card?.querySelector("[data-ping-message]");
      button.addEventListener("click", async () => {
        const originalText = button.textContent;
        button.disabled = true;
        button.textContent = "Pinging...";
        card?.classList.remove("ping-up", "ping-down");
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
          if (payload.ok) {
            card?.classList.add("ping-up");
            button.textContent = `Up - ${payload.latency_ms}ms`;
            if (message) {
              message.textContent = "Device responded successfully.";
            }
          } else {
            card?.classList.add("ping-down");
            button.textContent = "Down";
            if (message) {
              message.textContent = payload.error || "No response.";
            }
          }
        } catch (error) {
          card?.classList.add("ping-down");
          button.textContent = "Error";
          if (message) {
            message.textContent = error.message || "Ping could not be completed.";
          }
        } finally {
          setTimeout(() => {
            button.disabled = false;
            if (button.textContent === "Error") {
              button.textContent = originalText;
            }
          }, 900);
        }
      });
    });
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
        fieldset.querySelectorAll("[data-monitor-count]").forEach((input) => {
          const output = input.parentElement?.querySelector("[data-monitor-duration]");
          if (output) output.textContent = "Approximately " + (Number(input.value || 0) * seconds) + " seconds at the selected interval.";
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

  setupBulkEdit();
  setupQuickPing();
  setupMonitorThresholds();
})();
