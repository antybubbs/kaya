(() => {
  const form = document.querySelector("[data-ha-maintenance-advance]");
  if (!form) return;
  let advancing = false;
  let lastPhase = "";
  let terminal = false;
  let advanceTimer = null;

  const advance = async (phase) => {
    if (terminal || advancing || !phase) return;
    advancing = true;
    try {
      await fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: {Accept: "application/json"},
      });
    } finally {
      advancing = false;
    }
  };

  document.addEventListener("ha:live", (event) => {
    const maintenance = event.detail?.maintenance;
    if (!maintenance || maintenance.status !== "RUNNING") {
      if (maintenance && ["SUCCEEDED", "FAILED", "FAILED_SAFE", "PAUSED", "NEEDS_ATTENTION", "CANCELLED"].includes(maintenance.status)) {
        terminal = true;
        if (advanceTimer) window.clearTimeout(advanceTimer);
      }
      return;
    }
    const phase = String(maintenance.phase || "");
    if (!phase || phase === lastPhase) return;
    lastPhase = phase;
    advanceTimer = window.setTimeout(() => advance(phase), 500);
  });
})();
