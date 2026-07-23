document.addEventListener("DOMContentLoaded", () => {
  const root = document.querySelector("[data-ha-failover-live]");
  if (!root) return;
  const poll = async () => {
    try {
      const response = await fetch(root.dataset.statusUrl, {headers: {Accept: "application/json"}, cache: "no-store"});
      if (!response.ok) throw new Error("status unavailable");
      const state = await response.json();
      root.querySelector("[data-failover-status]").textContent = state.status.replaceAll("_", " ");
      root.querySelector("[data-failover-message]").textContent = state.message;
      const error = root.querySelector("[data-failover-error]");
      if (state.error) { error.hidden = false; error.querySelector("[data-failover-error-message]").textContent = state.error; }
      if (!state.running) window.setTimeout(() => window.location.replace(window.location.pathname + "?updated=1#failover-result"), 1200);
      else window.setTimeout(poll, 3000);
    } catch (_) { window.setTimeout(poll, 5000); }
  };
  window.setTimeout(poll, 1000);
});
