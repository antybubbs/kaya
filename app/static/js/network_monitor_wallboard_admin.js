(() => {
  const picker = document.querySelector("[data-wallboard-monitor-picker]");
  const orderInput = document.querySelector("[data-wallboard-monitor-order]");
  const selectedCounts = document.querySelectorAll("[data-wallboard-selected-count]");
  const syncOrder = () => {
    if (!picker || !orderInput) return;
    const selected = [...picker.querySelectorAll("[data-monitor-id]")].filter(row => row.querySelector('input[name="wallboard_monitor_ids"]').checked);
    orderInput.value = selected.map(row => row.dataset.monitorId).join(",");
    const allActive = [...picker.querySelectorAll('[data-monitor-enabled="true"]')].length;
    const count = document.querySelector('input[name="wallboard_monitor_scope"]:checked')?.value === "selected" ? selected.length : allActive;
    selectedCounts.forEach(output => { output.textContent = String(count); });
  };
  document.querySelector("[data-wallboard-monitor-search]")?.addEventListener("input", event => { const query = event.currentTarget.value.trim().toLowerCase(); picker?.querySelectorAll("[data-monitor-search]").forEach(row => { row.hidden = Boolean(query && !row.dataset.monitorSearch.includes(query)); }); });
  picker?.addEventListener("change", syncOrder);
  picker?.addEventListener("click", event => { const button = event.target.closest("[data-wallboard-order]"); if (!button) return; const row = button.closest("[data-monitor-id]"); if (button.dataset.wallboardOrder === "up" && row.previousElementSibling) picker.insertBefore(row, row.previousElementSibling); else if (button.dataset.wallboardOrder === "down" && row.nextElementSibling) picker.insertBefore(row.nextElementSibling, row); syncOrder(); button.focus(); });
  document.querySelector("[data-wallboard-copy-url]")?.addEventListener("click", async event => { const input = document.querySelector("[data-wallboard-url]"); const status = document.querySelector("[data-wallboard-url-status]"); try { await navigator.clipboard.writeText(input.value); event.currentTarget.textContent = "Copied"; status.textContent = "URL copied."; window.setTimeout(() => { event.currentTarget.textContent = "Copy"; }, 1500); } catch (_) { input.select(); status.textContent = "URL selected. Press Ctrl+C to copy."; } });
  document.querySelector("[data-wallboard-generate-url]")?.addEventListener("click", async event => {
    event.preventDefault(); event.stopImmediatePropagation();
    const button = event.currentTarget;
    if (button.dataset.wallboardConfirm && !confirm(button.dataset.wallboardConfirm)) return;
    const form = button.form;
    const status = document.querySelector("[data-wallboard-url-status]");
    const previousText = button.textContent;
    button.disabled = true; button.textContent = button.value === "regenerate" ? "Re-generating..." : "Generating..."; status.textContent = "";
    try {
      const body = new URLSearchParams({ csrf_token: form.querySelector('input[name="csrf_token"]').value, wallboard_action: button.value });
      const response = await fetch(button.formAction, { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", "X-Requested-With": "XMLHttpRequest" }, body: body.toString() });
      const result = await response.json();
      if (!response.ok || !result.url) throw new Error(result.detail || "The Wallboard URL could not be generated.");
      const input = document.querySelector("[data-wallboard-url]");
      input.value = result.url;
      document.querySelector("[data-wallboard-url-shell]").hidden = false;
      document.querySelector("[data-wallboard-url-empty]").hidden = true;
      const copy = document.querySelector("[data-wallboard-copy-url]");
      copy.hidden = false; copy.disabled = false;
      document.querySelector("[data-wallboard-url-summary]").textContent = "Generated";
      const revoke = document.querySelector("[data-wallboard-revoke-url]");
      if (revoke) { revoke.hidden = false; revoke.disabled = false; }
      button.value = "regenerate";
      button.textContent = "Re-generate URL";
      button.dataset.wallboardConfirm = "Re-generating this URL will immediately change the live Wallboard URL and invalidate all currently connected shared displays. Continue?";
      status.textContent = result.regenerated ? "The live Wallboard URL was changed." : "Wallboard URL generated.";
    } catch (error) {
      button.textContent = previousText;
      status.textContent = error.message || "The Wallboard URL could not be generated.";
    } finally { button.disabled = false; }
  });
  document.querySelectorAll("[data-wallboard-confirm]:not([data-wallboard-generate-url])").forEach(button => button.addEventListener("click", event => { if (!confirm(button.dataset.wallboardConfirm)) event.preventDefault(); }));

  const enabled = document.querySelector("[data-wallboard-enabled]");
  const syncEnabled = () => {
    const active = Boolean(enabled?.checked);
    document.querySelectorAll(".wallboard-shared-only").forEach(section => section.classList.toggle("is-inactive", !active));
    const status = document.querySelector("[data-wallboard-enabled-status]");
    if (status) { status.textContent = active ? "Enabled" : "Disabled"; status.classList.toggle("good", active); }
  };
  enabled?.addEventListener("change", syncEnabled); syncEnabled();

  const remember = document.querySelector("[data-wallboard-remember]");
  const rememberLifetime = document.querySelector("[data-wallboard-remember-lifetime]");
  const rememberSetting = document.querySelector("[data-wallboard-remember-setting]");
  const syncRemember = () => {
    if (!rememberLifetime) return;
    let fallback = document.querySelector("[data-wallboard-remember-fallback]");
    if (!remember?.checked && !fallback) { fallback = document.createElement("input"); fallback.type = "hidden"; fallback.name = rememberLifetime.name; fallback.value = rememberLifetime.value; fallback.dataset.wallboardRememberFallback = ""; rememberLifetime.before(fallback); }
    if (remember?.checked) fallback?.remove();
    rememberLifetime.disabled = !remember?.checked;
    rememberSetting?.classList.toggle("is-disabled", !remember?.checked);
  };
  remember?.addEventListener("change", syncRemember); syncRemember();

  const scopeInputs = document.querySelectorAll('input[name="wallboard_monitor_scope"]');
  const monitorSelection = document.querySelector("[data-wallboard-selected-monitors]");
  const syncScope = () => { if (monitorSelection) monitorSelection.hidden = document.querySelector('input[name="wallboard_monitor_scope"]:checked')?.value !== "selected"; syncOrder(); };
  scopeInputs.forEach(input => input.addEventListener("change", syncScope)); syncScope();

  const passcodeType = document.querySelector("[data-wallboard-passcode-type]");
  const passcode = document.querySelector("[data-wallboard-passcode]");
  const confirmation = document.querySelector("[data-wallboard-passcode-confirm]");
  const passcodeSubmit = document.querySelector("[data-wallboard-passcode-submit]");
  const syncPasscode = () => {
    const guidance = document.querySelector("[data-wallboard-passcode-guidance]");
    if (guidance) guidance.textContent = passcodeType?.value === "alphanumeric" ? "Use at least 8 characters, including a letter and number." : "Use at least 6 digits.";
    if (passcodeSubmit) passcodeSubmit.disabled = !passcode?.value || passcode.value !== confirmation?.value;
  };
  [passcodeType, passcode, confirmation].forEach(control => { control?.addEventListener("input", syncPasscode); control?.addEventListener("change", syncPasscode); }); syncPasscode();
  syncOrder();
})();
