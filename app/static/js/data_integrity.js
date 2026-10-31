(() => {
  // Data Integrity workspace. All server data is rendered with textContent, never as HTML.
  // Authorisation is enforced by the server; disabled controls here are conveniences only.
  const root = document.querySelector("[data-di-root]");
  if (!root) return;
  const csrf = document.body.dataset.csrfToken || "";
  const canRepair = root.dataset.canRepair === "1";
  const maxBulk = Number(root.dataset.maxBulk || 50);
  const api = "/api/data-integrity";
  const cache = new Map();

  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (value === false || value == null) return;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : String(value));
    });
    children.flat().forEach((child) => {
      if (child == null || child === false) return;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
    return node;
  };

  const when = (value) => {
    if (!value) return "—";
    const date = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`);
    return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  };
  const looksLikeTime = (key, value) => typeof value === "string" && /(_at|_end|started|ended)$/.test(key) && /^\d{4}-\d\d-\d\d/.test(value);
  const label = (key) => key.replace(/_/g, " ").replace(/\bid\b/i, "ID").replace(/^./, (char) => char.toUpperCase());
  const display = (key, value) => {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "boolean") return value ? "Yes" : "No";
    if (looksLikeTime(key, value)) return when(value);
    if (Array.isArray(value)) return value.length ? value.join(", ") : "—";
    return String(value);
  };

  async function request(method, url, body) {
    const response = await fetch(url, {
      method,
      credentials: "same-origin",
      headers: { Accept: "application/json", ...(body !== undefined ? { "Content-Type": "application/json" } : {}), ...(method !== "GET" ? { "X-CSRF-Token": csrf } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let payload = {};
    try { payload = await response.json(); } catch (_error) { payload = {}; }
    if (!response.ok) {
      const detail = typeof payload.detail === "string" ? payload.detail : Array.isArray(payload.detail) ? "The request was not valid." : `Request failed (${response.status}).`;
      const error = new Error(detail);
      error.status = response.status;
      error.payload = payload;
      throw error;
    }
    return payload;
  }

  const message = (kind, text) => el("p", { class: `di-message ${kind}`, role: kind === "error" ? "alert" : "status", text });

  // ------------------------------------------------------------ evidence rendering

  function table(rows) {
    const columns = [];
    rows.forEach((row) => Object.keys(row).forEach((key) => {
      if (!columns.includes(key) && typeof row[key] !== "object") columns.push(key);
    }));
    const shown = columns.slice(0, 9);
    return el("div", { class: "di-evidence-table" }, el("table", {},
      el("thead", {}, el("tr", {}, shown.map((key) => el("th", { scope: "col", text: label(key) })))),
      el("tbody", {}, rows.slice(0, 50).map((row) => el("tr", {}, shown.map((key) => el("td", { "data-label": label(key), text: display(key, row[key]) })))))));
  }

  function evidenceBlock(evidence, depth = 0) {
    const list = el("dl", { class: "di-kv" });
    const nested = [];
    Object.entries(evidence || {}).forEach(([key, value]) => {
      if (key === "subject") return;
      if (Array.isArray(value) && value.length && typeof value[0] === "object") {
        nested.push(el("section", { class: "di-evidence-group" }, el("h4", { text: label(key) }), table(value.map((row) => flatten(row)))));
      } else if (value && typeof value === "object" && !Array.isArray(value)) {
        if (depth < 1) nested.push(el("section", { class: "di-evidence-group" }, el("h4", { text: label(key) }), evidenceBlock(value, depth + 1)));
      } else {
        list.append(el("div", {}, el("dt", { text: label(key) }), el("dd", { text: display(key, value) })));
      }
    });
    return el("div", { class: "di-evidence" }, list.children.length ? list : null, nested);
  }

  function flatten(row) {
    const result = {};
    Object.entries(row).forEach(([key, value]) => {
      if (Array.isArray(value)) result[key] = value.length && typeof value[0] === "object" ? `${value.length} item(s)` : value.join(", ");
      else if (value && typeof value === "object") Object.entries(value).forEach(([inner, item]) => { if (typeof item !== "object") result[`${key}_${inner}`] = item; });
      else result[key] = value;
    });
    return result;
  }

  // ------------------------------------------------------------ remediation

  function parameterControls(action, finding, evidence) {
    const box = el("div", { class: "di-params" });
    if (action === "choose_mac_owner") {
      box.append(el("p", { class: "muted", text: "Select the asset that legitimately owns this MAC. Kaya never selects an owner automatically." }));
      (evidence.owners || []).forEach((owner) => box.append(el("label", { class: "checkbox-label" },
        el("input", { type: "radio", name: `owner-${finding.id}`, value: owner.asset_id, "data-param": "owner_asset_id" }),
        `${owner.asset_tag || owner.asset_name || `Asset #${owner.asset_id}`} — ${(owner.evidence || []).length} confirmed row(s), ${owner.asset_status || "status unknown"}`)));
    } else if (action === "keep_assignment") {
      box.append(el("p", { class: "muted", text: "Select the assignment that is genuinely current. The others are closed, not deleted." }));
      (evidence.assignments || []).forEach((row) => box.append(el("label", { class: "checkbox-label" },
        el("input", { type: "radio", name: `keep-${finding.id}`, value: row.assignment_id, "data-param": "keep_assignment_id" }),
        `#${row.assignment_id} · ${row.asset_tag || row.asset_name || `Asset #${row.asset_id}`} · ${row.provenance} · since ${when(row.started_at)}`)));
    } else if (action === "replace_hostname") {
      const options = evidence.observed_hostnames || [];
      if (!options.length) box.append(message("warning", "No alternative observed hostname is available."));
      else box.append(el("label", {}, "Observed hostname",
        el("select", { "data-param": "hostname" }, el("option", { value: "", text: "Select a hostname" }), options.map((name) => el("option", { value: name, text: name })))));
    } else if (action === "set_asset_hostname") {
      box.append(el("p", { class: "muted", text: "Set the linked asset's preferred hostname. Leave blank to explicitly clear its administrator preference." }));
      box.append(el("label", {}, "Hostname or FQDN", el("input", { type: "text", maxlength: "255", autocomplete: "off", "data-param": "hostname", placeholder: "device.example.invalid" })));
    }
    return box;
  }

  function readParams(container) {
    const params = {};
    container.querySelectorAll("[data-param]").forEach((input) => {
      if (input.type === "radio" && !input.checked) return;
      if (!input.value) return;
      params[input.dataset.param] = input.dataset.param === "hostname" ? input.value : Number(input.value);
    });
    return params;
  }

  function previewView(preview, finding, params, panel) {
    const wrap = el("div", { class: "di-preview", tabindex: "-1" });
    wrap.append(el("h4", { text: `Preview: ${preview.action_label}` }), el("p", { class: "muted", text: preview.description }));
    if (preview.changes.length) wrap.append(el("h5", { text: "Records that will change" }), table(preview.changes));
    if (preview.closes.length) wrap.append(el("h5", { text: "Assignments that will be closed" }), table(preview.closes));
    if (preview.revokes.length) wrap.append(el("h5", { text: "Evidence that will be revoked" }), table(preview.revokes));
    if (!preview.changes.length && !preview.closes.length && !preview.revokes.length) wrap.append(message("warning", "No record changes are required."));
    wrap.append(el("h5", { text: "Preserved" }), el("ul", {}, preview.preserved.map((text) => el("li", { text }))));
    if (preview.risks.length) wrap.append(el("h5", { text: "Risks" }), el("ul", { class: "di-risks" }, preview.risks.map((text) => el("li", { text }))));
    if (!canRepair) {
      wrap.append(message("warning", "You can preview repairs, but applying them requires the Data Integrity repair permission."));
      return wrap;
    }
    const confirmBox = el("input", { type: "checkbox" });
    const typed = preview.high_risk ? el("input", { type: "text", maxlength: "120", autocomplete: "off", "aria-label": `Type ${preview.confirmation_text} to confirm` }) : null;
    const apply = el("button", { type: "button", class: "button danger", disabled: true, text: "Apply fix" });
    const status = el("div", { role: "status", "aria-live": "polite" });
    const sync = () => {
      apply.disabled = !confirmBox.checked || (typed && typed.value.trim().toLowerCase() !== String(preview.confirmation_text).toLowerCase());
    };
    confirmBox.addEventListener("change", sync);
    if (typed) typed.addEventListener("input", sync);
    apply.addEventListener("click", async () => {
      apply.disabled = true;
      status.replaceChildren(message("info", "Applying under lock and re-validating…"));
      try {
        const result = await request("POST", `${api}/findings/${finding.id}/repair`, {
          action: preview.action, params, preview_token: preview.preview_token, confirmation: typed ? typed.value : null,
        });
        if (result.outcome === "applied" && result.verified) status.replaceChildren(message("success", "Repair applied and verified. The finding is resolved."));
        else if (result.outcome === "applied") status.replaceChildren(message("warning", `Repair applied, but the check still reports: ${result.remaining || "an inconsistency"}. The finding stays open.`));
        else status.replaceChildren(message("info", result.message || "Nothing was changed."));
        updateRow(finding.id, result.finding);
        cache.delete(finding.id);
        setTimeout(() => loadPanel(finding.id, panel, true), 900);
      } catch (error) {
        status.replaceChildren(message("error", error.status === 409 ? `${error.message} Use Preview fix again.` : error.message));
        sync();
      }
    });
    wrap.append(el("div", { class: "di-confirm" },
      el("label", { class: "checkbox-label" }, confirmBox, "I reviewed these changes and want to apply them"),
      typed ? el("label", {}, `Type ${preview.confirmation_text} to confirm this decision`, typed) : null,
      apply), status);
    return wrap;
  }

  function resolutionView(finding, evidence, panel) {
    const section = el("section", { class: "di-resolve", "aria-label": "Resolve this finding" });
    const output = el("div", { class: "di-resolve-output" });
    if (finding.actions.length) {
      section.append(el("h3", { text: "Choose resolution" }));
      const params = el("div");
      const radios = finding.actions.map((action, index) => el("label", { class: "checkbox-label di-action-choice" },
        el("input", { type: "radio", name: `action-${finding.id}`, value: action.key, checked: index === 0 }),
        el("span", {}, el("strong", { text: action.label }), el("small", { text: action.description }))));
      const choose = () => {
        const selected = section.querySelector(`input[name="action-${finding.id}"]:checked`);
        params.replaceChildren(parameterControls(selected.value, finding, evidence));
        output.replaceChildren();
      };
      radios.forEach((radio) => radio.querySelector("input").addEventListener("change", choose));
      const previewButton = el("button", { type: "button", text: "Preview fix" });
      previewButton.addEventListener("click", async () => {
        const action = section.querySelector(`input[name="action-${finding.id}"]:checked`).value;
        const values = readParams(params);
        previewButton.disabled = true;
        output.replaceChildren(message("info", "Calculating the change plan from current data…"));
        try {
          const preview = await request("POST", `${api}/findings/${finding.id}/preview`, { action, params: values });
          if (preview.state !== "ready") output.replaceChildren(message("warning", preview.message));
          else {
            const view = previewView(preview, finding, values, panel);
            output.replaceChildren(view);
            view.focus();
          }
        } catch (error) {
          output.replaceChildren(message("error", error.message));
        } finally {
          previewButton.disabled = false;
        }
      });
      section.append(el("div", { class: "di-action-list", role: "radiogroup", "aria-label": "Available corrective actions" }, radios), params, previewButton, output);
      choose();
    } else if (finding.status === "open" || finding.status === "needs_review") {
      section.append(el("h3", { text: "Manual review" }), el("p", { class: "muted", text: "No automatic correction is safe for this finding. Use the record links to review it, then ignore it with a reason once handled." }));
    }
    return section;
  }

  function lifecycleView(finding, panel) {
    const section = el("section", { class: "di-lifecycle" });
    const status = el("div", { role: "status", "aria-live": "polite" });
    const act = async (path, body, button) => {
      button.disabled = true;
      try {
        const result = await request("POST", `${api}/findings/${finding.id}/${path}`, body);
        status.replaceChildren(message("success", result.message || "Updated."));
        updateRow(finding.id, result.finding);
        cache.delete(finding.id);
        setTimeout(() => loadPanel(finding.id, panel, true), 700);
      } catch (error) {
        status.replaceChildren(message("error", error.message));
        button.disabled = false;
      }
    };
    const revalidate = el("button", { type: "button", class: "button secondary", text: "Revalidate now" });
    revalidate.addEventListener("click", () => act("revalidate", undefined, revalidate));
    const buttons = el("div", { class: "di-button-row" }, revalidate);
    finding.acknowledgements.forEach((item) => {
      const button = el("button", { type: "button", class: "button secondary", text: item.label });
      button.addEventListener("click", () => act("acknowledge", { acknowledgement: item.key, note: note.value || null }, button));
      buttons.append(button);
    });
    const note = el("textarea", { maxlength: "500", rows: "2", "aria-label": "Reason or note" });
    if (finding.status === "ignored") {
      const reopen = el("button", { type: "button", class: "button secondary", text: "Reopen finding" });
      reopen.addEventListener("click", () => act("reopen", undefined, reopen));
      buttons.append(reopen);
      section.append(el("h3", { text: "Review status" }), el("p", { class: "muted", text: `Ignored ${when(finding.ignored_at)}: ${finding.ignore_reason || ""}` }), buttons, status);
      return section;
    }
    if (finding.status === "resolved") {
      section.append(el("h3", { text: "Review status" }), el("p", { class: "muted", text: `Resolved (${finding.resolution || "verified"}) ${when(finding.resolved_at)}.` }), buttons, status);
      return section;
    }
    const ignore = el("button", { type: "button", class: "button secondary", text: "Ignore with reason" });
    ignore.addEventListener("click", () => {
      if (note.value.trim().length < 5) { status.replaceChildren(message("error", "Give a reason of at least 5 characters.")); note.focus(); return; }
      act("ignore", { reason: note.value }, ignore);
    });
    buttons.append(ignore);
    section.append(el("h3", { text: "Acknowledge or ignore" }), el("label", {}, "Reason or note (required to ignore)", note), buttons, status);
    return section;
  }

  function renderPanel(finding, panel) {
    const evidence = finding.live.detected && finding.live.evidence ? finding.live.evidence : finding.evidence;
    const live = finding.live.detected
      ? message(finding.live.changed_since_audit ? "warning" : "info", finding.live.changed_since_audit ? "Still present, but the evidence changed since the audit. The view below shows current data; revalidate to update the finding." : "Re-checked now: the inconsistency is still present.")
      : message("success", "Re-checked now: the inconsistency is no longer present. Revalidate to resolve the finding.");
    panel.replaceChildren(
      el("div", { class: "di-panel-grid" },
        el("section", { class: "di-explain" },
          el("h3", { text: finding.type_label }), live,
          el("h4", { text: "Why this was detected" }), el("p", { text: finding.why }),
          el("h4", { text: "Consequence" }), el("p", { text: finding.consequence }),
          el("h4", { text: "Recommended action" }), el("p", { text: finding.recommendation }),
          finding.links.length ? el("p", { class: "di-links" }, finding.links.map((link) => el("a", { href: link.href, text: link.label }))) : null),
        el("section", { class: "di-evidence-panel" }, el("h3", { text: finding.live.detected ? "Current evidence" : "Evidence at last audit" }), evidenceBlock(evidence))),
      resolutionView(finding, evidence, panel),
      lifecycleView(finding, panel),
      el("details", { class: "di-events" }, el("summary", { text: `History (${finding.events.length})` }),
        el("ol", {}, finding.events.map((event) => el("li", {}, el("strong", { text: label(event.event) }), ` · ${when(event.created_at)}${event.actor ? ` · ${event.actor}` : ""}`)))));
  }

  async function loadPanel(id, panel, force = false) {
    if (!force && cache.has(id)) { renderPanel(cache.get(id), panel); return; }
    panel.replaceChildren(message("info", "Loading and re-checking against current data…"));
    try {
      const finding = await request("GET", `${api}/findings/${id}`);
      cache.set(id, finding);
      renderPanel(finding, panel);
    } catch (error) {
      panel.replaceChildren(message("error", error.message));
    }
  }

  function updateRow(id, row) {
    if (!row) return;
    const tr = document.querySelector(`[data-di-row="${CSS.escape(String(id))}"]`);
    if (!tr) return;
    const status = tr.querySelector(".di-status");
    if (status) { status.className = `di-status ${row.status}`; status.textContent = row.status_label; }
    const box = tr.querySelector("[data-di-select]");
    if (box && !row.bulk_repairable) { box.checked = false; box.disabled = true; syncSelection(); }
  }

  document.querySelectorAll("[data-di-investigate]").forEach((button) => button.addEventListener("click", () => {
    const id = Number(button.dataset.diInvestigate);
    const row = document.getElementById(`di-panel-${id}`);
    const open = row.hidden;
    row.hidden = !open;
    button.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) {
      const panel = row.querySelector("[data-di-panel]");
      loadPanel(id, panel);
      panel.focus();
    }
  }));

  // ------------------------------------------------------------ audit runs

  const runButton = document.querySelector("[data-di-run]");
  const runState = document.querySelector("[data-di-run-state]");

  function showProgress(active) {
    runState.replaceChildren(
      el("span", { class: "status-pill warning", text: active.status === "queued" ? "Queued" : "Running" }),
      el("span", { text: `Audit #${active.id} — ${active.progress_done} of ${active.progress_total} checks` }),
      el("progress", { max: active.progress_total, value: active.progress_done, "aria-label": "Audit progress" }));
  }

  async function poll() {
    try {
      const state = await request("GET", `${api}/audits/current`);
      if (state.active) {
        showProgress(state.active);
        setTimeout(poll, 2000);
        return;
      }
      runState.replaceChildren(message(state.last_finished && state.last_finished.status === "completed" ? "success" : "warning",
        `Audit ${state.last_finished ? state.last_finished.status : "finished"}. Reloading results…`));
      setTimeout(() => window.location.reload(), 800);
    } catch (error) {
      runState.replaceChildren(message("error", error.message));
      runButton.disabled = false;
      runButton.textContent = "Run Audit";
    }
  }

  runButton.addEventListener("click", async () => {
    runButton.disabled = true;
    runButton.textContent = "Audit running…";
    try {
      const result = await request("POST", `${api}/audits`);
      showProgress(result.queued);
    } catch (error) {
      if (error.status !== 409) {
        runState.replaceChildren(message("error", error.message));
        runButton.disabled = false;
        runButton.textContent = "Run Audit";
        return;
      }
      if (error.payload.active) showProgress(error.payload.active);
    }
    setTimeout(poll, 1500);
  });
  if (runButton.disabled) setTimeout(poll, 1500);

  // ------------------------------------------------------------ bulk repair

  const selectAll = document.querySelector("[data-di-select-all]");
  const selected = () => [...document.querySelectorAll("[data-di-select]:checked")].map((box) => Number(box.value));
  const countLabel = document.querySelector("[data-di-selected-count]");
  const bulkPreview = document.querySelector("[data-di-bulk-preview]");
  function syncSelection() {
    if (!countLabel) return;
    const ids = selected();
    countLabel.textContent = `${ids.length} selected`;
    bulkPreview.disabled = !ids.length || ids.length > maxBulk;
  }
  document.querySelectorAll("[data-di-select]").forEach((box) => box.addEventListener("change", syncSelection));
  if (selectAll) selectAll.addEventListener("change", () => {
    document.querySelectorAll("[data-di-select]:not(:disabled)").forEach((box) => { box.checked = selectAll.checked; });
    syncSelection();
  });

  const bulkDialog = document.querySelector("[data-di-bulk]");
  const bulkBody = document.querySelector("[data-di-bulk-body]");
  const bulkConfirm = document.querySelector("[data-di-bulk-confirm]");
  const bulkExecute = document.querySelector("[data-di-bulk-execute]");
  let bulkItems = [];
  if (bulkPreview) bulkPreview.addEventListener("click", async () => {
    bulkBody.replaceChildren(message("info", "Previewing every selected repair against current data…"));
    bulkConfirm.checked = false;
    bulkExecute.disabled = true;
    bulkItems = [];
    bulkDialog.showModal();
    try {
      const result = await request("POST", `${api}/bulk/preview`, { finding_ids: selected() });
      bulkItems = result.items.map((item) => ({ finding_id: item.finding_id, preview_token: item.preview_token }));
      bulkBody.replaceChildren(
        el("p", { text: `${result.items.length} repair(s) ready with ${result.change_count} record change(s); ${result.skipped.length} skipped.` }),
        result.items.length ? el("ol", { class: "di-bulk-list" }, result.items.map((item) => el("li", {},
          el("strong", { text: item.affected_label }), el("small", { text: ` ${item.action_label}` }),
          item.changes.length ? table(item.changes) : null, item.closes.length ? table(item.closes) : null))) : null,
        result.skipped.length ? el("section", {}, el("h3", { text: "Skipped (not safe for bulk repair)" }),
          el("ul", {}, result.skipped.map((row) => el("li", { text: `Finding ${row.finding_id}: ${row.reason}` })))) : null);
    } catch (error) {
      bulkBody.replaceChildren(message("error", error.message));
    }
  });
  if (bulkConfirm) bulkConfirm.addEventListener("change", () => { bulkExecute.disabled = !bulkConfirm.checked || !bulkItems.length; });
  if (bulkExecute) bulkExecute.addEventListener("click", async () => {
    bulkExecute.disabled = true;
    bulkConfirm.disabled = true;
    try {
      const result = await request("POST", `${api}/bulk/repair`, { items: bulkItems, confirmation: "APPLY BULK REPAIRS" });
      bulkItems = [];  // a batch is applied once; preview again for further repairs
      bulkConfirm.checked = false;
      const headline = result.status === "completed" ? message("success", `All ${result.requested} repairs applied.`)
        : result.status === "partial" ? message("warning", `Partially completed: ${result.succeeded} of ${result.requested} succeeded. Review the failures below.`)
        : message("error", `No repairs were applied (${result.requested} requested).`);
      bulkBody.replaceChildren(headline, el("ul", { class: "di-bulk-results" }, result.results.map((row) => el("li", { class: row.outcome },
        el("strong", { text: `Finding ${row.finding_id}: ${label(row.outcome)}` }), row.message ? ` — ${row.message}` : ""))),
        el("button", { type: "button", class: "button secondary", text: "Reload findings", onclick: () => window.location.reload() }));
    } catch (error) {
      bulkBody.prepend(message("error", error.message));
    } finally {
      bulkConfirm.disabled = false;
    }
  });

  // ------------------------------------------------------------ history

  const historyDialog = document.querySelector("[data-di-history]");
  let chart = null;
  document.querySelector("[data-di-history-open]").addEventListener("click", async () => {
    historyDialog.showModal();
    const body = document.querySelector("[data-di-history-rows]");
    try {
      const result = await request("GET", `${api}/history`);
      const runs = result.runs;
      body.replaceChildren(...(runs.length ? runs.map((run) => el("tr", {},
        el("td", { "data-label": "Audit", text: `#${run.id}` }), el("td", { "data-label": "Trigger", text: label(run.trigger) }),
        el("td", { "data-label": "Status" }, el("span", { class: `di-status ${run.status}`, text: label(run.status) })),
        el("td", { "data-label": "Completed", text: when(run.completed_at) }), el("td", { "data-label": "Open", text: run.open }),
        el("td", { "data-label": "Critical", text: run.critical }), el("td", { "data-label": "New", text: run.new }),
        el("td", { "data-label": "Resolved", text: run.resolved }), el("td", { "data-label": "Reopened", text: run.reopened }),
        el("td", { "data-label": "Duration", text: run.duration_ms != null ? `${(run.duration_ms / 1000).toFixed(1)} s` : "—" })))
        : [el("tr", {}, el("td", { colspan: "10", text: "No audits have run yet." }))]));
      const finished = runs.filter((run) => run.status === "completed" || run.status === "incomplete");
      const compare = document.querySelector("[data-di-history-compare]");
      if (finished.length >= 2) {
        const [latest, previous] = finished;
        const delta = (a, b) => (a - b > 0 ? `+${a - b}` : `${a - b}`);
        compare.replaceChildren(el("p", { text: `Audit #${latest.id} compared with #${previous.id}: open ${delta(latest.open, previous.open)}, critical ${delta(latest.critical, previous.critical)}, ${latest.new} new, ${latest.resolved} resolved, ${latest.reopened} reopened.` }));
      } else compare.replaceChildren(el("p", { class: "muted", text: "Comparison appears after two completed audits." }));
      const chartElement = document.querySelector("[data-di-history-chart]");
      if (window.echarts && finished.length) {
        const ordered = [...finished].reverse();
        const style = getComputedStyle(chartElement);
        const token = (name, fallback) => style.getPropertyValue(name).trim() || fallback;
        chart = chart || window.echarts.init(chartElement);
        chart.setOption({
          animation: false,
          textStyle: { color: token("--k-text", "#e6e9ee") },
          grid: { left: 40, right: 16, top: 36, bottom: 30 },
          legend: { top: 0, textStyle: { color: token("--k-muted", "#8d97a6") } },
          tooltip: { trigger: "axis" },
          xAxis: { type: "category", data: ordered.map((run) => `#${run.id}`), axisLabel: { color: token("--k-muted", "#8d97a6") } },
          yAxis: { type: "value", minInterval: 1, axisLabel: { color: token("--k-muted", "#8d97a6") }, splitLine: { lineStyle: { color: token("--k-divider", "#1a2028") } } },
          series: [
            ["Open", "open", token("--k-amber", "#f5a524")], ["Critical", "critical", token("--k-red", "#ff6b6b")],
            ["New", "new", token("--k-blue", "#6fb4ff")], ["Resolved", "resolved", token("--k-green", "#3ecf8e")], ["Reopened", "reopened", "#c084fc"],
          ].map(([name, field, color]) => ({ name, type: "line", data: ordered.map((run) => run[field]), itemStyle: { color }, lineStyle: { color }, symbolSize: 6 })),
        });
        chart.resize();
      } else chartElement.replaceChildren(el("p", { class: "muted", text: "Trends appear after the first completed audit." }));
    } catch (error) {
      body.replaceChildren(el("tr", {}, el("td", { colspan: "10" }, message("error", error.message))));
    }
  });
  document.querySelectorAll("[data-di-close]").forEach((button) => button.addEventListener("click", () => button.closest("dialog").close()));
  window.addEventListener("resize", () => chart && chart.resize());

  // ------------------------------------------------------------ schedule

  const settings = document.querySelector("[data-di-settings]");
  settings.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.querySelector("[data-di-settings-status]");
    try {
      await request("POST", `${api}/settings`, { schedule_hours: settings.schedule_hours.value, notify_critical: settings.notify_critical.checked });
      status.textContent = "Schedule saved.";
    } catch (error) {
      status.textContent = error.message;
    }
  });
})();
