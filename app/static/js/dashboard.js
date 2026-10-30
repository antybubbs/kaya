(() => {
  "use strict";
  const root = document.querySelector("[data-dashboard]");
  if (!root) return;
  const config = JSON.parse(root.dataset.config || "{}");
  const grid = root.querySelector("[data-dashboard-grid]");
  const zones = { main: root.querySelector('[data-zone="main"]'), rail: root.querySelector('[data-zone="rail"]') };
  const live = root.querySelector(".cc-live");
  const label = root.querySelector("[data-live-label]");
  const liveAnnounce = root.querySelector("[data-live-announce]");
  const saveState = root.querySelector("[data-save-state]");
  const csrf = root.dataset.csrfToken;
  const INTERVAL = Math.max(10000, (config.poll_interval_seconds || 10) * 1000);
  const DELAYED_MS = INTERVAL + Math.max(5000, INTERVAL / 2), STALE_MS = INTERVAL * 2, LOST_FAILURES = 3;
  const RANGES = config.traffic_ranges || ["1h", "24h", "7d", "30d"];
  let layout = config.layout, inFlight = false, queued = false, timer = null, tickTimer = null, failures = 0, lastSuccess = 0, liveState = "live";
  let editing = false, dragged = null, dragArmed = false, managerDirty = false;
  let trafficRange = RANGES.includes(config.default_traffic_range) ? config.default_traffic_range : "24h";
  let uptimeHosts = [];
  layout.uptime_hidden = Array.isArray(layout.uptime_hidden) ? layout.uptime_hidden : [];

  // ----------------------------------------------------------------- formatting
  const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const number = new Intl.NumberFormat("en-GB");
  const unavailable = (cls = "") => `<span class="cc-unavailable ${cls}">Unavailable</span>`;
  const isNum = value => typeof value === "number" && Number.isFinite(value);
  const sig = value => value >= 100 ? value.toFixed(0) : value >= 10 ? value.toFixed(1).replace(/\.0$/, "") : value.toFixed(2).replace(/\.?0+$/, "");
  function scaled(value, units, base) { let index = 0; let current = Math.max(0, value); while (current >= base && index < units.length - 1) { current /= base; index++; } return [sig(current), units[index]]; }
  const rate = bps => scaled(bps, ["bps", "Kbps", "Mbps", "Gbps", "Tbps"], 1000);
  const bytes = value => scaled(value, ["B", "KB", "MB", "GB", "TB", "PB"], 1000);
  const ago = iso => { if (!iso) return ""; const seconds = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000)); if (seconds < 60) return `${seconds}s`; if (seconds < 3600) return `${Math.floor(seconds / 60)} min`; if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`; return `${Math.floor(seconds / 86400)}d`; };
  const agoLong = iso => iso ? `${ago(iso)} ago` : "";
  const kpi = (labelText, pair, cls = "") => `<div class="cc-kpi"><span class="cc-lbl">${escapeHtml(labelText)}</span>${pair ? `<span class="cc-kpi-value ${cls}">${escapeHtml(pair[0])}<span class="cc-unit"> ${escapeHtml(pair[1])}</span></span>` : `<span class="cc-kpi-value cc-unavailable">Unavailable</span>`}</div>`;

  // ----------------------------------------------------------------- renderers
  function niceMax(value) { if (!value || value <= 0) return 1; const exponent = Math.pow(10, Math.floor(Math.log10(value))); const fraction = value / exponent; const step = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 2.5 ? 2.5 : fraction <= 5 ? 5 : 10; return step * exponent; }
  function timeLabel(ms, spanMs) { const date = new Date(ms); if (spanMs <= 86400000 * 1.01) return date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" }); return date.toLocaleDateString("en-GB", { day: "numeric", month: "short" }); }
  function chart(data) {
    const points = (data.points || []).map(p => ({ t: new Date(p.at).getTime(), i: Number(p.in_bps) || 0, o: Number(p.out_bps) || 0 })).filter(p => Number.isFinite(p.t)).sort((a, b) => a.t - b.t);
    if (!points.length) return `<div class="cc-chart-empty" role="img" aria-label="Network traffic chart: no data yet for the ${escapeHtml(data.range_label)}">No data yet</div>`;
    const W = 600, H = 240, start = new Date(data.start).getTime(), end = new Date(data.end).getTime(), span = Math.max(1, end - start);
    const top = niceMax(Math.max(...points.map(p => Math.max(p.i, p.o))));
    const x = t => ((t - start) / span * W).toFixed(1), y = v => (H - v / top * H).toFixed(1);
    const gap = (data.bucket_seconds || 300) * 1000 * 1.5;
    const segments = []; let current = [];
    points.forEach((p, index) => { if (index && p.t - points[index - 1].t > gap) { segments.push(current); current = []; } current.push(p); });
    segments.push(current);
    const line = (seg, key) => seg.map((p, index) => `${index ? "L" : "M"}${x(p.t)} ${y(p[key])}`).join(" ");
    const area = (seg, key) => `${line(seg, key)} L${x(seg[seg.length - 1].t)} ${H} L${x(seg[0].t)} ${H} Z`;
    const series = (key, colour, opacity) => segments.map(seg => seg.length > 1 ? `<path d="${area(seg, key)}" fill="${colour}" fill-opacity="${opacity}"></path><path d="${line(seg, key)}" fill="none" stroke="${colour}" stroke-width="2.5" vector-effect="non-scaling-stroke"></path>` : `<circle cx="${x(seg[0].t)}" cy="${y(seg[0][key])}" r="2.5" fill="${colour}"></circle>`).join("");
    const ticks = [1, .76, .5, .24, 0].map(f => rate(top * f));
    const times = Array.from({ length: 7 }, (_, index) => index === 6 ? "Now" : timeLabel(start + span * index / 6, span));
    const inPeak = rate(Math.max(...points.map(p => p.i))), outPeak = rate(Math.max(...points.map(p => p.o)));
    const aria = `Inbound and outbound gateway traffic over the ${data.range_label}: inbound peaked at ${inPeak.join(" ")}, outbound peaked at ${outPeak.join(" ")}, from ${points.length} data points`;
    const css = getComputedStyle(root);
    const blue = css.getPropertyValue("--cc-blue").trim() || "#6fb4ff", amber = css.getPropertyValue("--cc-amber").trim() || "#f5a524", gridColour = css.getPropertyValue("--cc-divider-2").trim() || "#1c222b", base = css.getPropertyValue("--cc-control").trim() || "#2a3340";
    return `<div class="cc-chart"><div class="cc-yaxis" aria-hidden="true">${ticks.map(t => `<span>${escapeHtml(t.join(" "))}</span>`).join("")}</div><div class="cc-chart-plot"><svg role="img" aria-label="${escapeHtml(aria)}" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">${[0.5, 60, 120, 180].map(v => `<line x1="0" y1="${v}" x2="${W}" y2="${v}" stroke="${gridColour}" vector-effect="non-scaling-stroke"></line>`).join("")}<line x1="0" y1="239.5" x2="${W}" y2="239.5" stroke="${base}" vector-effect="non-scaling-stroke"></line>${series("i", blue, 0.14)}${series("o", amber, 0.12)}</svg><div class="cc-xaxis" aria-hidden="true">${times.map(t => `<span>${escapeHtml(t)}</span>`).join("")}</div></div></div>`;
  }
  function renderTraffic(body, data) {
    const card = body.closest("[data-widget-key]"), rangeLabel = card.querySelector("[data-traffic-range-label]");
    if (rangeLabel) rangeLabel.textContent = data.range_label;
    const kpis = `<div class="cc-kpis">${kpi("Inbound", isNum(data.inbound_bps) ? rate(data.inbound_bps) : null, "is-in")}${kpi("Outbound", isNum(data.outbound_bps) ? rate(data.outbound_bps) : null, "is-out")}${kpi("Peak · " + data.range, isNum(data.peak_bps) ? rate(data.peak_bps) : null)}${kpi("Transferred", isNum(data.transferred_bytes) ? bytes(data.transferred_bytes) : null)}${kpi("Blocked by DNS", isNum(data.dns_blocked_percentage) ? [data.dns_blocked_percentage.toFixed(1), "%"] : null)}</div>`;
    if (!data.configured) { body.innerHTML = `${kpis}<div class="cc-chart-empty" role="img" aria-label="Network traffic chart: no traffic source is configured">No data yet</div><p class="cc-note">No WAN traffic source is configured. Add an SNMPv3 source in the Uptime module to collect gateway throughput.</p>`; return; }
    let vlans = "";
    if (data.vlans && data.vlans.tiles.length) {
      vlans = `<div class="cc-vlans">${data.vlans.tiles.map(v => `<div class="cc-vlan"><div class="cc-vlan-row"><span class="cc-vlan-name" title="${escapeHtml(v.name)}">${escapeHtml(v.name)}</span>${isNum(v.bps) ? `<span class="cc-vlan-rate">${escapeHtml(rate(v.bps).join(" "))}</span>` : `<span class="cc-vlan-rate cc-unavailable">Unavailable</span>`}</div><div class="cc-track" role="img" aria-label="${escapeHtml(v.name)}: ${isNum(v.bps) ? escapeHtml(rate(v.bps).join(" ")) + ", " + (Number(v.share) || 0) + "% of the busiest VLAN" : "no current usage data"}"><i style="width:${Math.max(0, Math.min(100, Number(v.share) || 0))}%"></i></div></div>`).join("")}</div>${data.vlans.total > data.vlans.tiles.length ? `<p class="cc-note">Showing ${data.vlans.tiles.length} of ${Number(data.vlans.total) || 0} VLANs.</p>` : ""}`;
    } else if (data.vlans) vlans = `<p class="cc-note">No VLANs are recorded in VLAN / IP Manager.</p>`;
    else vlans = `<p class="cc-note">Per-VLAN usage is unavailable. It requires VLAN / IP Manager access.</p>`;
    body.innerHTML = kpis + chart(data) + vlans;
  }
  function renderUptime(body, data) {
    const card = body.closest("[data-widget-key]");
    const intervals = data.interval_seconds || [];
    card.querySelector("[data-uptime-interval]").textContent = intervals.length === 0 ? "– seconds" : intervals.length === 1 ? `${intervals[0]} seconds` : `${intervals[0]}–${intervals[intervals.length - 1]} seconds`;
    card.querySelector("[data-uptime-shown]").textContent = data.shown_count;
    card.querySelector("[data-uptime-total]").textContent = data.total;
    uptimeHosts = data.hosts || [];
    renderPicker(card);
    const stat = (text, value, cls = "") => `<div class="cc-stat"><span class="cc-lbl">${escapeHtml(text)}</span>${value === null || value === undefined ? `<span class="cc-stat-value cc-unavailable">Unavailable</span>` : `<span class="cc-stat-value ${cls}">${escapeHtml(value)}</span>`}</div>`;
    const summary = `<div class="cc-uptime-summary">${stat("Overall · shown hosts", data.overall, "is-good")}${stat("Incidents", data.incidents)}${stat("Longest uptime", data.longest_uptime)}</div>`;
    const rows = data.rows.length ? data.rows.map(r => `<div class="cc-uptime-row"><a class="cc-host-link" href="/networking/ip-wan-monitor/${encodeURIComponent(r.id)}"><span class="cc-dot is-${escapeHtml(r.state)}" aria-hidden="true"></span><span>${escapeHtml(r.name)}</span></a><div class="cc-strip" role="img" aria-label="${escapeHtml(r.aria)}">${r.days.map(d => `<span class="is-${escapeHtml(d)}"></span>`).join("")}</div>${r.percent ? `<span class="cc-pct${r.perfect ? " is-perfect" : ""}">${escapeHtml(r.percent)}</span>` : `<span class="cc-pct cc-unavailable">No data</span>`}</div>`).join("") : data.total ? `<div class="cc-empty-box">No hosts selected. Use Choose hosts to pick what appears here.</div>` : `<div class="cc-empty-box">The Uptime module has no checks yet.</div>`;
    body.innerHTML = `${summary}<div class="cc-uptime-rows">${rows}</div><div class="cc-legend"><span><i class="cc-swatch is-operational"></i>Operational</span><span><i class="cc-swatch is-degraded"></i>Degraded</span><span><i class="cc-swatch is-outage"></i>Outage</span></div>`;
  }
  function renderPicker(card) {
    const options = card.querySelector("[data-uptime-options]");
    if (!options || card.querySelector("[data-uptime-picker]").hidden) return;
    const hidden = new Set(layout.uptime_hidden);
    options.innerHTML = uptimeHosts.length ? uptimeHosts.map(h => `<label class="cc-host-option"><input type="checkbox" data-uptime-host="${escapeHtml(h.id)}" ${hidden.has(h.id) ? "" : "checked"}><span>${escapeHtml(h.name)}</span>${h.kind ? `<span class="cc-host-kind">${escapeHtml(h.kind)}</span>` : ""}</label>`).join("") : `<p class="cc-empty">The Uptime module has no checks yet.</p>`;
  }
  function renderModules(body, data) {
    const value = row => {
      if (row.value === null || row.value === undefined) return `<span class="cc-card-value cc-unavailable">Unavailable</span>`;
      const text = typeof row.value === "object" && row.value.relative ? agoLong(row.value.relative) : typeof row.value === "number" ? number.format(row.value) : String(row.value);
      return `<span class="cc-card-value${row.tone === "warn" ? " is-warn" : ""}" title="${escapeHtml(text)}">${escapeHtml(text)}</span>`;
    };
    body.innerHTML = data.cards.length ? data.cards.map(c => `<a href="${escapeHtml(c.target)}" class="cc-module-card"><div class="cc-card-head"><span class="cc-card-title">${escapeHtml(c.title)}</span><span class="cc-dot is-${escapeHtml(c.state)}" role="img" aria-label="${c.state === "warn" ? "Needs attention" : c.state === "ok" ? "Healthy" : "No data"}"></span></div><div class="cc-card-rows">${c.rows.map(r => `<div class="cc-card-row"><span>${escapeHtml(r.label)}</span>${value(r)}</div>`).join("")}</div></a>`).join("") : `<p class="cc-empty">You don't have access to any module summaries.</p>`;
  }
  function renderAttention(body, data) {
    const counts = data.counts || {}, items = data.items || [];
    const tile = (cls, value, text) => `<div class="cc-count ${cls}${value ? " has-items" : ""}"><strong>${number.format(value || 0)}</strong><span class="cc-lbl">${text}</span></div>`;
    const level = s => s === "critical" ? "critical" : s === "warning" ? "warning" : "info";
    const list = items.length ? `<div class="cc-alerts">${items.map(x => `<a href="${escapeHtml(x.target || "#")}" class="cc-alert"><span class="cc-alert-top"><span class="cc-severity is-${level(x.severity)}">${escapeHtml(level(x.severity) === "info" ? "Info" : x.severity)}</span>${x.detected_at ? `<time datetime="${escapeHtml(x.detected_at)}" title="${escapeHtml(x.detected_at)}">${escapeHtml(ago(x.detected_at))}</time>` : ""}</span><span class="cc-alert-title">${escapeHtml(x.summary)}</span><span class="cc-alert-meta">${escapeHtml([x.module, (x.objects || []).join(", "), x.count > 1 ? `${x.count}×` : ""].filter(Boolean).join(" · "))}</span></a>`).join("")}</div>` : `<p class="cc-empty">No current issues need attention.</p>`;
    body.innerHTML = `<div class="cc-counts">${tile("is-critical", counts.critical, "Critical")}${tile("is-warning", counts.warning, "Warning")}${tile("is-info", counts.information, "Info")}</div>${list}`;
  }
  function renderInfrastructure(body, data) {
    const gauge = (text, value, colour) => { const shown = isNum(value) ? `${value.toFixed(1)}%` : null; return `<div class="cc-gauge"><div class="cc-gauge-row"><span>${text}</span>${shown ? `<span class="cc-num">${shown}</span>` : unavailable()}</div><div class="cc-gauge-track" role="img" aria-label="${text} ${shown || "unavailable"}"><i class="${colour}" style="width:${shown ? Math.max(0, Math.min(100, value)) : 0}%"></i></div></div>`; };
    const pair = (a, b) => isNum(a) && isNum(b) ? `<span class="cc-num">${number.format(a)} / ${number.format(b)}</span>` : unavailable();
    body.innerHTML = `${gauge("CPU", data.cpu_percent, "is-green")}${gauge("Memory", data.memory_percent, "is-blue")}${gauge("Storage", data.storage_percent, "is-blue")}<div class="cc-infra-foot"><div><span>Hosts online</span>${pair(data.online_hosts, data.hosts)}</div><div><span>Running</span>${pair(data.running, data.workloads)}</div></div>`;
  }
  function renderLegacy(body, key, data) {
    if (data.metrics) { body.innerHTML = `<div class="cc-metrics">${data.metrics.map(m => `<div><span>${escapeHtml(m.label)}</span><strong class="cc-num">${escapeHtml(typeof m.value === "number" ? number.format(m.value) : m.value)}</strong></div>`).join("")}</div>`; return; }
    const items = data.items || [];
    body.innerHTML = items.length ? `<div class="cc-alerts">${items.map(x => `<a href="${escapeHtml(x.target || "#")}" class="cc-alert"><span class="cc-alert-top"><span class="cc-severity is-info">${escapeHtml(x.severity || "info")}</span><time title="${escapeHtml(x.detected_at || "")}">${escapeHtml(ago(x.detected_at))}</time></span><span class="cc-alert-title">${escapeHtml(x.summary)}</span>${x.object || x.count > 1 ? `<span class="cc-alert-meta">${escapeHtml([x.object, x.count > 1 ? `${x.count}×` : ""].filter(Boolean).join(" · "))}</span>` : ""}</a>`).join("")}</div>` : `<p class="cc-empty">No recent activity.</p>`;
  }
  const renderers = { network_traffic: renderTraffic, uptime: renderUptime, module_overview: renderModules, attention_required: renderAttention, infrastructure_summary: renderInfrastructure };
  function renderWidget(card, result) {
    const body = card.querySelector("[data-widget-body]");
    if (!result || result.status !== "ok") {
      card.classList.add("is-error");
      if (!body.dataset.hasData) body.innerHTML = `<p class="cc-empty">${escapeHtml(result?.reason || "Data is temporarily unavailable")}</p>`;
      return;
    }
    card.classList.remove("is-error");
    const key = card.dataset.widgetKey;
    (renderers[key] || ((b, d) => renderLegacy(b, key, d)))(body, result.data);
    body.dataset.hasData = "1";
    const age = card.querySelector("[data-source-age]");
    if (age) age.title = config.show_source_age && result.data.source_updated_at ? `Source updated ${agoLong(result.data.source_updated_at)}` : "";
  }

  // ----------------------------------------------------------------- live refresh
  function setLive(state, text) { if (state !== liveState && liveAnnounce) liveAnnounce.textContent = state === "live" ? "Live data restored" : text; liveState = state; live.dataset.liveState = state; label.textContent = text; }
  function liveText() { return `Live · updated ${Math.max(0, Math.round((Date.now() - lastSuccess) / 1000))}s ago`; }
  async function refresh() {
    if (inFlight) { queued = true; return; }
    if (document.hidden) return; if (!navigator.onLine) { setLive("lost", "Offline"); return; } inFlight = true;
    try {
      const response = await fetch(`/api/dashboard/snapshot?range=${encodeURIComponent(trafficRange)}`, { headers: { Accept: "application/json" }, cache: "no-store" });
      if (response.status === 401 || response.status === 403) { stop(); setLive("lost", "Session expired"); return; }
      if (!response.ok) throw new Error();
      const data = await response.json();
      Object.entries(data.widgets || {}).forEach(([key, value]) => { const card = grid.querySelector(`[data-widget-key="${CSS.escape(key)}"]`); if (card) renderWidget(card, value); });
      lastSuccess = Date.now(); failures = 0; setLive("live", liveText());
    } catch (_error) { failures++; setLive(failures >= LOST_FAILURES ? "lost" : "delayed", failures >= LOST_FAILURES ? "Connection lost" : "Delayed"); }
    finally { inFlight = false; if (queued) { queued = false; refresh(); } }
  }
  function tick() { if (!lastSuccess) return; const elapsed = Date.now() - lastSuccess; if (elapsed >= STALE_MS) setLive("stale", "Stale"); else if (elapsed >= DELAYED_MS) setLive("delayed", "Delayed"); else if (liveState === "live") label.textContent = liveText(); }
  function stop() { clearInterval(timer);clearInterval(tickTimer); timer = null; tickTimer = null; }
  function start() { stop(); refresh(); timer = setInterval(refresh, INTERVAL); tickTimer = setInterval(tick, 1000); }

  // ----------------------------------------------------------------- preferences
  async function putLayout() { const response = await fetch("/api/dashboard/preferences", { method: "PUT", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(layout) }); if (!response.ok) throw new Error(); layout = (await response.json()).layout; }
  async function save() { try { await putLayout(); saveState.textContent = "Dashboard layout saved"; setTimeout(() => saveState.textContent = "", 2500); } catch (_) { saveState.textContent = "Could not save dashboard layout"; } }
  const panels = () => [...zones.main.children, ...zones.rail.children].filter(el => el.matches("[data-widget-key]"));
  function syncOrder() { panels().forEach((card, index) => { const row = layout.widgets.find(item => item.key === card.dataset.widgetKey); if (row) { row.position = index + 1; row.width = card.dataset.width; row.zone = card.parentElement === zones.rail ? "rail" : "main"; } }); save(); }

  // ----------------------------------------------------------------- traffic range
  grid.addEventListener("click", event => {
    const button = event.target.closest("[data-traffic-range]");
    if (!button || !RANGES.includes(button.dataset.trafficRange)) return;
    trafficRange = button.dataset.trafficRange;
    button.parentElement.querySelectorAll("[data-traffic-range]").forEach(item => item.setAttribute("aria-pressed", String(item === button)));
    refresh();
  });

  // ----------------------------------------------------------------- uptime picker
  const uptimeCard = grid.querySelector('[data-widget-key="uptime"]');
  if (uptimeCard) {
    const picker = uptimeCard.querySelector("[data-uptime-picker]"), opener = uptimeCard.querySelector("button[aria-controls]"), status = uptimeCard.querySelector("[data-uptime-save-state]");
    const setOpen = open => { picker.hidden = !open; opener.setAttribute("aria-expanded", String(open)); if (open) renderPicker(uptimeCard); else opener.focus(); };
    const persist = async previous => { status.textContent = "Saving…"; try { await putLayout(); status.textContent = "Saved"; refresh(); } catch (_) { layout.uptime_hidden = previous; renderPicker(uptimeCard); status.textContent = "Could not save your selection"; } };
    uptimeCard.addEventListener("click", event => {
      if (event.target.closest("[data-uptime-picker-toggle]")) { setOpen(picker.hidden); return; }
      const select = event.target.closest("[data-uptime-select]");
      if (!select) return;
      const previous = [...layout.uptime_hidden];
      layout.uptime_hidden = select.dataset.uptimeSelect === "all" ? [] : uptimeHosts.map(h => h.id);
      renderPicker(uptimeCard); persist(previous);
    });
    uptimeCard.addEventListener("change", event => {
      const box = event.target.closest("[data-uptime-host]");
      if (!box) return;
      const id = Number(box.dataset.uptimeHost), previous = [...layout.uptime_hidden];
      layout.uptime_hidden = box.checked ? previous.filter(item => item !== id) : [...new Set([...previous, id])];
      persist(previous);
    });
    picker.addEventListener("keydown", event => { if (event.key === "Escape") { event.preventDefault(); setOpen(false); } });
  }

  // ----------------------------------------------------------------- edit mode
  const coarsePointer = window.matchMedia("(pointer: coarse)");
  function move(card, up) {
    const zone = card.parentElement, sibling = up ? card.previousElementSibling : card.nextElementSibling;
    if (sibling) { zone.insertBefore(card, up ? sibling : sibling.nextElementSibling); return true; }
    if (up && zone === zones.rail) { zones.main.appendChild(card); return true; }
    if (!up && zone === zones.main) { zones.rail.insertBefore(card, zones.rail.firstElementChild); return true; }
    return false;
  }
  root.querySelector("[data-edit-dashboard]")?.addEventListener("click", event => { editing = !editing; root.classList.toggle("is-editing", editing); event.currentTarget.setAttribute("aria-pressed", String(editing)); event.currentTarget.textContent = editing ? "Finish editing" : "Edit dashboard"; panels().forEach(card => card.draggable = editing && !coarsePointer.matches); });
  grid.addEventListener("pointerdown", event => { dragArmed = Boolean(event.target.closest("[data-drag-handle]")); });
  grid.addEventListener("dragstart", event => { if (!editing || !dragArmed) { event.preventDefault(); return; } dragged = event.target.closest("[data-widget-key]"); dragged.classList.add("is-dragging"); });
  grid.addEventListener("dragover", event => {
    if (!dragged) return; event.preventDefault();
    const target = event.target.closest("[data-widget-key]");
    if (target && target !== dragged) target.parentElement.insertBefore(dragged, target);
    else if (!target) { const zone = event.target.closest("[data-zone]"); if (zone && dragged.parentElement !== zone) zone.appendChild(dragged); }
  });
  grid.addEventListener("dragend", () => { dragArmed = false; if (dragged) { dragged.classList.remove("is-dragging"); dragged = null; syncOrder(); } });
  grid.addEventListener("keydown", event => { const handle = event.target.closest("[data-drag-handle]"); if (!editing || !handle || !event.altKey || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) return; event.preventDefault(); if (move(handle.closest("[data-widget-key]"), ["ArrowLeft", "ArrowUp"].includes(event.key))) { syncOrder(); handle.focus(); } });
  grid.addEventListener("click", event => { const button = event.target.closest("[data-widget-move]"); if (!editing || !button) return; if (move(button.closest("[data-widget-key]"), button.dataset.widgetMove === "up")) { syncOrder(); button.focus(); } });
  grid.addEventListener("change", event => { if (!event.target.matches("[data-widget-size]")) return; const card = event.target.closest("[data-widget-key]"); card.classList.remove(...["small", "medium", "large", "full"].map(x => `cc-w-${x}`)); card.classList.add(`cc-w-${event.target.value}`); card.dataset.width = event.target.value; syncOrder(); });

  // ----------------------------------------------------------------- widget manager
  const dialog = root.querySelector("[data-widget-manager]");
  function updateManagerCount() { const enabled = layout.widgets.filter(x => x.enabled).length; const count = dialog.querySelector("[data-widget-enabled-count]"); if (count) count.textContent = `${enabled} of ${(config.widgets || []).length} widgets enabled`; }
  root.querySelector("[data-manage-widgets]")?.addEventListener("click", () => { managerDirty = false; const options = dialog.querySelector("[data-widget-options]"); options.innerHTML = (config.widgets || []).map(def => { const row = layout.widgets.find(x => x.key === def.key); const status = def.available ? (row?.enabled ? "Shown" : "Hidden") : def.availability_reason; return `<label class="widget-option ${!def.available ? "is-unavailable" : ""}"><span class="widget-option-copy"><span class="widget-option-heading"><strong>${escapeHtml(def.name)}</strong><em class="widget-option-status">${escapeHtml(status)}</em></span><small>${escapeHtml(def.module)}</small><p>${escapeHtml(def.description)}</p>${!def.available ? `<span class="widget-unavailable-reason">${escapeHtml(def.availability_reason)}</span>` : ""}</span><span class="widget-toggle"><input type="checkbox" data-widget-toggle="${escapeHtml(def.key)}" aria-label="Show ${escapeHtml(def.name)}" ${row?.enabled ? "checked" : ""} ${!def.available ? "disabled" : ""}><i aria-hidden="true"></i></span></label>`; }).join(""); updateManagerCount(); dialog.querySelector("[data-widget-manager-saved]").textContent = ""; dialog.showModal(); });
  dialog?.addEventListener("change", async event => { if (!event.target.matches("[data-widget-toggle]")) return; const row = layout.widgets.find(x => x.key === event.target.dataset.widgetToggle); if (!row) return; row.enabled = event.target.checked; managerDirty = true; const card = event.target.closest(".widget-option"); card.querySelector(".widget-option-status").textContent = row.enabled ? "Shown" : "Hidden"; updateManagerCount(); const saved = dialog.querySelector("[data-widget-manager-saved]"); saved.textContent = "Saving…"; try { await putLayout(); saved.textContent = "Saved"; } catch (_) { row.enabled = !row.enabled; event.target.checked = row.enabled; card.querySelector(".widget-option-status").textContent = row.enabled ? "Shown" : "Hidden"; updateManagerCount(); saved.textContent = "Could not save"; } });
  dialog?.addEventListener("close", () => { if (managerDirty) location.reload(); });
  dialog?.querySelector("[data-reset-dashboard]")?.addEventListener("click", async () => { if (!confirm("Reset your dashboard to the site defaults?")) return; const response = await fetch("/api/dashboard/preferences/reset", { method: "POST", headers: { "X-CSRF-Token": csrf } }); if (response.ok) location.reload(); });

  // ----------------------------------------------------------------- monitor mode
  const monitorButton = root.querySelector("[data-monitor-mode]");
  function applyMonitor(active) { root.classList.toggle("is-monitor-mode", active); document.documentElement.classList.toggle("dashboard-monitor-mode", active); monitorButton?.setAttribute("aria-pressed", String(active)); }
  monitorButton?.addEventListener("click", () => { layout.monitor_mode = !root.classList.contains("is-monitor-mode"); applyMonitor(layout.monitor_mode); save(); });
  if (layout.monitor_mode) applyMonitor(true);

  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); }); window.addEventListener("online", refresh); window.addEventListener("pagehide", stop); window.addEventListener("pageshow", event => { if(event.persisted)start(); }); start();
})();
