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

  setupBulkEdit();
  setupQuickPing();
})();
