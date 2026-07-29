(() => {
  const root = document.querySelector("[data-wallboard], [data-dashboard-layout]");
  if (!root) return;
  try { document.documentElement.dataset.kayaTheme = localStorage.getItem("kaya-theme") || "command"; } catch (_) {}
  const body = document.body;
  const grid = root.querySelector("[data-monitor-live-grid]");
  const controls = document.querySelector("[data-wallboard-controls]");
  const saveState = document.querySelector("[data-wallboard-save-state]");
  const shared = root.dataset.shared === "true";
  const headers = shared ? { "Content-Type": "application/json", "X-Wallboard-CSRF": root.dataset.wallboardCsrf } : { "Content-Type": "application/json", "X-CSRF-Token": root.dataset.csrf };
  let editMode = false;
  let dragAllowed = false;
  let dragged = null;
  let touchDragging = false;
  let saveTimer = null;
  let initialPreferences = {};
  try { initialPreferences = JSON.parse(root.dataset.preferences || "{}"); } catch (_) {}

  function preferences() {
    const value = { ...initialPreferences, monitor_order: grid ? [...grid.querySelectorAll("[data-monitor-card]")].map(card => Number(card.dataset.monitorCard)) : (initialPreferences.monitor_order || []) };
    if (body.dataset.wallboardColumns) value.columns = body.dataset.wallboardColumns;
    if (body.dataset.wallboardDensity) value.density = body.dataset.wallboardDensity;
    document.querySelectorAll("[data-wallboard-setting]").forEach(control => { value[control.dataset.wallboardSetting] = control.type === "checkbox" ? control.checked : control.value; });
    return value;
  }
  async function save() {
    if (!root.dataset.preferencesEndpoint) return;
    saveState.textContent = "Saving...";
    try {
      const response = await fetch(root.dataset.preferencesEndpoint, { method: "PUT", headers, body: JSON.stringify(preferences()), cache: "no-store" });
      if (!response.ok) throw new Error();
      saveState.textContent = "Saved";
    } catch (_) { saveState.textContent = "Could not save layout"; }
  }
  function queueSave() { window.clearTimeout(saveTimer); saveTimer = window.setTimeout(save, 250); }
  function applySetting(control) {
    const key = control.dataset.wallboardSetting;
    const value = control.type === "checkbox" ? String(control.checked) : control.value;
    if (key === "columns") body.dataset.wallboardColumns = value;
    else if (key === "density") body.dataset.wallboardDensity = value;
    else body.setAttribute(`data-${key.replaceAll("_", "-")}`, value);
    window.dispatchEvent(new Event("resize"));
    queueSave();
  }
  document.querySelectorAll("[data-wallboard-setting]").forEach(control => control.addEventListener("change", () => applySetting(control)));
  document.querySelectorAll("[data-wallboard-controls-toggle]").forEach(button => button.addEventListener("click", () => { controls.hidden = !controls.hidden; button.setAttribute("aria-expanded", String(!controls.hidden)); }));
  document.querySelector("[data-wallboard-controls-close]")?.addEventListener("click", () => { controls.hidden = true; });
  document.addEventListener("keydown", event => { if (event.key === "Escape" && controls && !controls.hidden) controls.hidden = true; });
  document.querySelectorAll("[data-wallboard-fullscreen]").forEach(button => button.addEventListener("click", async () => { try { if (document.fullscreenElement) await document.exitFullscreen(); else await document.documentElement.requestFullscreen(); } catch (_) {} }));
  document.addEventListener("fullscreenchange", () => { document.querySelectorAll("[data-wallboard-fullscreen]").forEach(button => { button.textContent = document.fullscreenElement ? "Exit full screen" : "Full screen"; }); });
  document.querySelector("[data-wallboard-theme]")?.addEventListener("click", () => { const theme = document.documentElement.dataset.kayaTheme === "light-ops" ? "command" : "light-ops"; document.documentElement.dataset.kayaTheme = theme; try { localStorage.setItem("kaya-theme", theme); } catch (_) {} });
  const clock = document.querySelector("[data-wallboard-clock]");
  const tick = () => { if (clock) { const now = new Date(); clock.dateTime = now.toISOString(); clock.textContent = now.toLocaleTimeString(); } };
  tick(); window.setInterval(tick, 1000);

  function setEdit(enabled) {
    editMode = enabled; body.classList.toggle("is-editing-layout", enabled);
    grid?.querySelectorAll("[data-monitor-card]").forEach(card => { card.draggable = enabled; });
    grid?.querySelectorAll("[data-monitor-drag-handle]").forEach(handle => { handle.hidden = !enabled; handle.disabled = !enabled; });
    grid?.querySelectorAll(".monitor-keyboard-order").forEach(controls => {
      controls.hidden = !enabled;
      controls.querySelectorAll("[data-monitor-move]").forEach(button => { button.disabled = !enabled; });
    });
  }
  const editLayout = document.querySelector("[data-wallboard-edit-layout]");
  editLayout?.addEventListener("change", event => setEdit(event.currentTarget.checked));
  setEdit(Boolean(editLayout?.checked));
  if (grid) grid.addEventListener("pointerdown", event => { dragAllowed = Boolean(event.target.closest("[data-monitor-drag-handle]")); if (editMode && dragAllowed && event.pointerType !== "mouse") { dragged = event.target.closest("[data-monitor-card]"); touchDragging = Boolean(dragged); dragged?.classList.add("is-dragging"); event.preventDefault(); } });
  window.addEventListener("pointermove", event => { if (!touchDragging || !dragged || !grid) return; const target = document.elementFromPoint(event.clientX, event.clientY)?.closest("[data-monitor-card]"); if (!target || target === dragged) return; const box = target.getBoundingClientRect(); grid.insertBefore(dragged, event.clientY > box.top + box.height / 2 ? target.nextSibling : target); event.preventDefault(); }, { passive: false });
  window.addEventListener("pointerup", () => { if (!touchDragging) return; dragged?.classList.remove("is-dragging"); dragged = null; touchDragging = false; dragAllowed = false; queueSave(); });
  if (grid) grid.addEventListener("dragstart", event => { const card = event.target.closest("[data-monitor-card]"); if (!editMode || !dragAllowed || !card) { event.preventDefault(); return; } dragged = card; card.classList.add("is-dragging"); event.dataTransfer.effectAllowed = "move"; });
  if (grid) grid.addEventListener("dragover", event => { if (!dragged) return; event.preventDefault(); const target = event.target.closest("[data-monitor-card]"); if (!target || target === dragged) return; const box = target.getBoundingClientRect(); const after = event.clientY > box.top + box.height / 2 || (Math.abs(event.clientY - (box.top + box.height / 2)) < box.height / 3 && event.clientX > box.left + box.width / 2); grid.insertBefore(dragged, after ? target.nextSibling : target); });
  if (grid) grid.addEventListener("dragend", () => { if (dragged) dragged.classList.remove("is-dragging"); dragged = null; dragAllowed = false; queueSave(); });
  if (grid) grid.addEventListener("click", event => { const button = event.target.closest("[data-monitor-move]"); if (!button || !editMode) return; const card = button.closest("[data-monitor-card]"); if (button.dataset.monitorMove === "up" && card.previousElementSibling) grid.insertBefore(card, card.previousElementSibling); else if (button.dataset.monitorMove === "down" && card.nextElementSibling) grid.insertBefore(card.nextElementSibling, card); else return; button.focus(); queueSave(); });
  document.querySelector("[data-wallboard-reset]")?.addEventListener("click", async () => { if (!confirm("Reset your IP/WAN Wallboard layout?")) return; const response = await fetch(root.dataset.resetEndpoint, { method: "POST", headers: { "X-CSRF-Token": root.dataset.csrf }, cache: "no-store" }); if (response.ok) location.reload(); });
})();
