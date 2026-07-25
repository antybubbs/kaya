(() => {
  const form = document.querySelector("[data-ha-maintenance-advance]");
  if (!form) return;
  let advancing = false;
  let lastPhase = "";

  const advance = async (phase) => {
    if (advancing || !phase) return;
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
      if (maintenance && ["SUCCEEDED", "FAILED_SAFE", "CANCELLED"].includes(maintenance.status)) {
        window.location.reload();
      }
      return;
    }
    const phase = String(maintenance.phase || "");
    if (phase !== lastPhase) lastPhase = phase;
    window.setTimeout(() => advance(phase), 500);
  });
})();
