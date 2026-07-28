(function () {
  const tabs = document.querySelector(".detail-tabs");
  const panels = ["overview", "performance", "incidents", "checks", "settings"].map((id) => document.getElementById(id)).filter(Boolean);
  if (tabs && panels.length) {
    const showTab = () => {
      const selected = panels.some((panel) => `#${panel.id}` === window.location.hash) ? window.location.hash.slice(1) : "overview";
      panels.forEach((panel) => { panel.hidden = panel.id !== selected; });
      tabs.querySelectorAll("a").forEach((link) => link.classList.toggle("active", link.hash === `#${selected}`));
      window.setTimeout(() => window.dispatchEvent(new Event("resize")), 0);
    };
    window.addEventListener("hashchange", showTab);
    showTab();
  }

  const detail = document.querySelector("[data-monitor-chart]");
  if (detail && window.echarts) {
    let payload = null;
    try {
      payload = JSON.parse(detail.dataset.monitorChart || "{}");
    } catch (_) {
      payload = { points: [], incidents: [], thresholds: {} };
    }
    const points = Array.isArray(payload.points) ? payload.points : [];
    const detailColors = chartTheme();
    const textColor = getComputedStyle(document.documentElement).getPropertyValue("--text").trim() || detailColors.tooltipText;
    const mutedColor = detailColors.axis;
    const gridColor = detailColors.grid;
    const timeValue = (point, key) => [Date.parse(point.at), point[key] == null ? null : Number(point[key]), statusLevel(point.status)];
    const incidentLines = (payload.incidents || []).map((incident) => ({
      name: `Incident #${incident.id}`,
      xAxis: Date.parse(incident.start),
      lineStyle: { color: "#ef4444", width: 1 },
      label: { show: false },
    }));
    const incidentAreas = (payload.incidents || []).filter((incident) => incident.end).map((incident) => ([
      { name: `Incident #${incident.id}`, xAxis: Date.parse(incident.start) },
      { xAxis: Date.parse(incident.end) },
    ]));
    const axis = {
      axisLine: { lineStyle: { color: gridColor } }, axisTick: { show: false },
      axisLabel: { color: mutedColor }, splitLine: { lineStyle: { color: gridColor } },
    };
    const charts = [];
    const miniCharts = [];
    const latencyElement = detail.querySelector("[data-monitor-latency-chart]");
    if (latencyElement && points.length) {
      const chart = window.echarts.init(latencyElement, null, { renderer: "canvas" });
      chart.setOption({
        animationDuration: 350, backgroundColor: "transparent", textStyle: { color: textColor },
        grid: { left: 18, right: 24, top: 24, bottom: 62, containLabel: true },
        tooltip: { trigger: "axis", confine: true, extraCssText: "max-width:min(280px,80vw);white-space:normal;overflow-wrap:anywhere;", backgroundColor: detailColors.tooltipBackground, borderColor: detailColors.tooltipBorder, textStyle: { color: detailColors.tooltipText }, valueFormatter: (value) => value == null ? "-" : formatLatency(value) },
        toolbox: { right: 8, feature: { dataZoom: {}, restore: {}, saveAsImage: { name: "kaya-monitor-latency" } }, iconStyle: { borderColor: mutedColor } },
        xAxis: { type: "time", ...axis }, yAxis: { type: "value", name: "ms", min: 0, ...axis },
        visualMap: { show: false, dimension: 2, seriesIndex: 0, pieces: statePieces(detailColors) },
        dataZoom: [{ type: "inside", filterMode: "none" }, { type: "slider", height: 20, bottom: 12, borderColor: gridColor, textStyle: { color: mutedColor } }],
        series: [{
          name: "Latency", type: "line", smooth: .24, showSymbol: false, connectNulls: false,
          lineStyle: { width: 2 }, areaStyle: { opacity: .08 },
          data: points.map((point) => timeValue(point, "latency")),
          markLine: { silent: false, symbol: "none", data: [
            { name: "Warning", yAxis: Number(payload.thresholds?.warning || 0), lineStyle: { color: "#f59e0b", type: "dashed" }, label: { color: "#fbbf24" } },
            { name: "Critical", yAxis: Number(payload.thresholds?.critical || 0), lineStyle: { color: "#ef4444", type: "dashed" }, label: { color: "#fca5a5" } },
            ...incidentLines,
          ] },
          markArea: { silent: true, itemStyle: { color: "rgba(239,68,68,.08)" }, data: incidentAreas },
        }],
      });
      chart.getZr().on("dblclick", () => chart.dispatchAction({ type: "dataZoom", start: 0, end: 100 }));
      detail.querySelector('[data-chart-export="latency"]')?.addEventListener("click", () => {
        const link = document.createElement("a");
        link.download = "kaya-monitor-latency.png";
        link.href = chart.getDataURL({ type: "png", pixelRatio: 2, backgroundColor: document.documentElement.dataset.kayaTheme === "light-ops" ? "#ffffff" : "#0f1218" });
        link.click();
      });
      charts.push(chart);
    } else {
      detail.querySelector("[data-chart-empty]")?.removeAttribute("hidden");
    }

    const latencyValues = points.map((point) => point.latency == null ? null : Number(point.latency));
    const miniData = {
      latency: points.map((point) => timeValue(point, "latency")),
      loss: points.map((point) => timeValue(point, "loss")),
      jitter: points.map((point, index) => [Date.parse(point.at), index && latencyValues[index] != null && latencyValues[index - 1] != null ? Math.abs(latencyValues[index] - latencyValues[index - 1]) : null]),
      availability: points.map((point) => [Date.parse(point.at), ["down", "offline"].includes(point.status) ? 0 : 100]),
    };
    detail.querySelectorAll("[data-monitor-mini]").forEach((element) => {
      const key = element.dataset.monitorMini;
      const chart = window.echarts.init(element, null, { renderer: "canvas" });
      chart.setOption({ animation: false, grid: { left: 2, right: 2, top: 5, bottom: 2, containLabel: true }, xAxis: { type: "time", show: false }, yAxis: { type: "value", show: false, min: key === "availability" ? 0 : null, max: key === "availability" ? 100 : null }, series: [{ type: "line", smooth: .2, showSymbol: false, connectNulls: false, lineStyle: { color: key === "loss" ? detailColors.warning : detailColors.healthy, width: 1.5 }, areaStyle: { opacity: .08 }, data: miniData[key] || [] }] });
      charts.push(chart);
      miniCharts.push({ chart, key });
    });
    window.addEventListener("resize", () => charts.forEach((chart) => chart.resize()));
    const detailThemeObserver = new MutationObserver((mutations) => {
      if (!mutations.some((mutation) => mutation.attributeName === "data-kaya-theme")) return;
      const colors = chartTheme();
      charts.forEach((chart) => chart.setOption({
        textStyle: { color: getComputedStyle(document.documentElement).getPropertyValue("--text").trim() || colors.tooltipText },
        tooltip: { backgroundColor: colors.tooltipBackground, borderColor: colors.tooltipBorder, textStyle: { color: colors.tooltipText } },
        xAxis: { axisLine: { lineStyle: { color: colors.line } }, axisLabel: { color: colors.axis }, splitLine: { lineStyle: { color: colors.grid } } },
        yAxis: { axisLine: { lineStyle: { color: colors.line } }, axisLabel: { color: colors.axis }, splitLine: { lineStyle: { color: colors.grid } } },
        visualMap: { pieces: statePieces(colors) },
      }, { notMerge: false, lazyUpdate: true, silent: true }));
      miniCharts.forEach(({ chart, key }) => chart.setOption({
        series: [{ lineStyle: { color: key === "loss" ? colors.warning : colors.healthy } }],
      }, { notMerge: false, lazyUpdate: true, silent: true }));
    });
    detailThemeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-kaya-theme"] });
    window.addEventListener("pagehide", () => {
      detailThemeObserver.disconnect();
      charts.forEach((chart) => chart.dispose());
    }, { once: true });
  }

  const container = document.querySelector("[data-monitor-content]");
  const liveGrid = document.querySelector("[data-monitor-live-grid]");
  if (!container || !liveGrid || !window.echarts) {
    return;
  }

  const liveWindowMs = 5 * 60 * 1000;
  const refreshSelect = document.querySelector("[data-monitor-refresh-rate]");
  const storageKey = "kaya.ipWanMonitor.dashboardRate";
  const clientKey = "kaya.ipWanMonitor.dashboardClient";
  const pollDelays = { live: 1000, five: 5000, ten: 10000, sixty: 60000 };
  let clientId = window.sessionStorage.getItem(clientKey);
  if (!clientId) {
    clientId = window.crypto?.randomUUID?.() || `dashboard-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    window.sessionStorage.setItem(clientKey, clientId);
  }
  const cards = new Map();
  let afterId = Number(liveGrid.dataset.latestObservationId || 0);
  let pollTimer = null;
  let clockTimer = null;
  let leaseTimer = null;
  let traceFrame = null;
  let lastTraceDraw = 0;
  let polling = false;
  let stopped = false;
  let activeRequest = null;
  let feedFailed = false;

  function parseSeries(element) {
    try {
      const values = JSON.parse(element.dataset.monitorSeries || "[]");
      return Array.isArray(values) ? values : [];
    } catch (_) {
      return [];
    }
  }

  function statusLevel(status) {
    return {
      healthy: 0, up: 0, warning: 1, critical: 2, offline: 3, down: 3,
      maintenance: 4, recovering: 5, paused: 6, unknown: 7,
    }[status] ?? 7;
  }

  function formatLatency(value) {
    if (value == null || !Number.isFinite(Number(value))) return "-";
    const numeric = Number(value);
    if (numeric >= 0 && numeric < 1) return "<1 ms";
    return `${Math.round(numeric * 10) / 10} ms`;
  }

  function formatLiveLatency(value) {
    if (value == null || !Number.isFinite(Number(value))) return "-";
    return `${Number(value).toFixed(3).replace(/\.?0+$/, "")} ms`;
  }

  function chartTheme() {
    const light = document.documentElement.dataset.kayaTheme === "light-ops";
    return light ? {
      axis: "rgba(15,23,42,.68)", line: "rgba(15,23,42,.16)", grid: "rgba(15,23,42,.08)",
      tooltipBackground: "#ffffff", tooltipBorder: "rgba(15,23,42,.18)", tooltipText: "#0f172a",
      healthy: "#16a34a", warning: "#d97706", critical: "#dc2626", offline: "#b91c1c",
      maintenance: "#2563eb", recovering: "#65a30d", paused: "#64748b", unknown: "#64748b",
    } : {
      axis: "#94a3b8", line: "rgba(148,163,184,.22)", grid: "rgba(148,163,184,.10)",
      tooltipBackground: "#111827", tooltipBorder: "#374151", tooltipText: "#f8fafc",
      healthy: "#22c55e", warning: "#f59e0b", critical: "#ef4444", offline: "#ef4444",
      maintenance: "#38bdf8", recovering: "#a3e635", paused: "#94a3b8", unknown: "#64748b",
    };
  }

  function statePieces(theme) {
    return [
      { value: 0, color: theme.healthy }, { value: 1, color: theme.warning },
      { value: 2, color: theme.critical }, { value: 3, color: theme.offline },
      { value: 4, color: theme.maintenance }, { value: 5, color: theme.recovering },
      { value: 6, color: theme.paused }, { value: 7, color: theme.unknown },
    ];
  }

  function axisBounds(points) {
    const values = points.map((point) => point.latency).filter((value) => Number.isFinite(value));
    if (!values.length) return { min: 0, max: 10 };
    const minimum = Math.min(...values);
    const maximum = Math.max(...values);
    const range = maximum - minimum;
    if (range < 4) {
      return { min: Math.max(0, Math.floor(minimum - 2)), max: Math.ceil(maximum + 3) };
    }
    const padding = Math.max(range * .15, 1);
    return { min: Math.max(0, Math.floor(minimum - padding)), max: Math.ceil(maximum + padding) };
  }

  function presentationSeries(card, now) {
    const data = card.points.map((point) => [point.time, point.latency, statusLevel(point.status)]);
    const latest = card.points[card.points.length - 1];
    if (latest && Number.isFinite(latest.latency) && now > latest.time) {
      data.push([now, latest.latency, statusLevel(latest.status)]);
    }
    return data;
  }

  function chartOption(card, now) {
    const bounds = axisBounds(card.points);
    const theme = chartTheme();
    const downMarkers = card.points.filter((point) => point.status === "down" || point.status === "offline").map((point) => ({
      xAxis: point.time, lineStyle: { color: "#ef4444", width: 1 }, label: { show: false },
    }));
    if (card.incidentStart) downMarkers.push({ xAxis: card.incidentStart, lineStyle: { color: "#ef4444", width: 2 }, label: { show: false } });
    return {
      animation: false,
      backgroundColor: "transparent",
      grid: { left: 12, right: 20, top: 18, bottom: 12, containLabel: true },
      tooltip: {
        trigger: "axis", confine: true, extraCssText: "max-width:min(260px,80vw);white-space:normal;overflow-wrap:anywhere;", backgroundColor: theme.tooltipBackground, borderColor: theme.tooltipBorder,
        textStyle: { color: theme.tooltipText, fontSize: 11 },
        formatter: (parameters) => {
          const item = parameters.find((entry) => entry.seriesName === "Response time");
          if (!item) return "No response";
          const point = card.points.find((candidate) => candidate.time === item.value[0]);
          const at = new Date(item.value[0]).toLocaleTimeString();
          const latency = item.value[1] == null ? "No response" : formatLiveLatency(item.value[1]);
          return `${at}<br>${latency}<br>${point?.status || "unknown"}`;
        },
      },
      xAxis: {
        type: "time", min: now - liveWindowMs, max: now + 250,
        axisLine: { lineStyle: { color: theme.line } }, axisTick: { show: false },
        axisLabel: { color: theme.axis, fontSize: 9, hideOverlap: true }, splitLine: { show: true, lineStyle: { color: theme.grid } },
      },
      yAxis: {
        type: "value", min: bounds.min, max: bounds.max, name: "ms", nameTextStyle: { color: theme.axis, fontSize: 9 },
        axisLine: { show: false }, axisTick: { show: false }, axisLabel: { color: theme.axis, fontSize: 9 },
        splitLine: { lineStyle: { color: theme.grid } },
      },
      visualMap: {
        show: false, dimension: 2, seriesIndex: 0,
        pieces: statePieces(theme),
      },
      series: [{
        id: `latency-${card.id}`, name: "Response time", type: "line", smooth: .12, showSymbol: false, clip: true, connectNulls: false,
        lineStyle: { width: 2 }, areaStyle: { opacity: .06 },
        data: presentationSeries(card, now),
        markLine: {
          silent: true, symbol: "none",
          data: [
            { yAxis: card.warning, lineStyle: { color: "rgba(245,158,11,.48)", type: "dashed" }, label: { show: false } },
            { yAxis: card.critical, lineStyle: { color: "rgba(239,68,68,.48)", type: "dashed" }, label: { show: false } },
            ...downMarkers,
          ],
        },
      }],
    };
  }

  function updateFeedState(card, now) {
    const state = card.element.querySelector("[data-monitor-feed-state]");
    if (!state) return;
    state.className = "monitor-feed-state";
    if (!card.enabled) {
      state.classList.add("paused");
      state.textContent = "Paused";
      return;
    }
    if (refreshSelect?.value === "paused") {
      state.className = "monitor-feed-state paused";
      state.textContent = "● Paused";
      return;
    }
    if (feedFailed) {
      state.className = "monitor-feed-state failed";
      state.textContent = "● Reconnecting";
      return;
    }
    const delayedAfter = Math.max(15000, card.interval * 2500);
    if (!card.lastChecked || now - card.lastChecked > delayedAfter) {
      state.className = "monitor-feed-state delayed";
      state.textContent = "● Delayed";
      return;
    }
    state.className = "monitor-feed-state live";
    state.textContent = "● Live";
  }

  function prunePoints(card, now) {
    const previousLength = card.points.length;
    const cutoff = now - liveWindowMs;
    const beforeWindow = card.points.filter((point) => point.time < cutoff).pop();
    card.points = card.points.filter((point) => point.time >= cutoff);
    if (beforeWindow) card.points.unshift(beforeWindow);
    for (const id of [...card.seen]) {
      if (!card.points.some((point) => point.id === id)) card.seen.delete(id);
    }
    return previousLength !== card.points.length;
  }

  function chartUpdateOption(card, now) {
    const bounds = axisBounds(card.points);
    const downMarkers = card.points.filter((point) => point.status === "down" || point.status === "offline").map((point) => ({
      xAxis: point.time, lineStyle: { color: chartTheme().offline, width: 1 }, label: { show: false },
    }));
    if (card.incidentStart) downMarkers.push({ xAxis: card.incidentStart, lineStyle: { color: chartTheme().offline, width: 2 }, label: { show: false } });
    return {
      xAxis: { min: now - liveWindowMs, max: now + 250 },
      yAxis: { min: bounds.min, max: bounds.max },
      series: [{
        id: `latency-${card.id}`,
        data: presentationSeries(card, now),
        markLine: { silent: true, symbol: "none", data: [
          { yAxis: card.warning, lineStyle: { color: "rgba(245,158,11,.48)", type: "dashed" }, label: { show: false } },
          { yAxis: card.critical, lineStyle: { color: "rgba(239,68,68,.48)", type: "dashed" }, label: { show: false } },
          ...downMarkers,
        ] },
      }],
    };
  }

  function renderCard(card, now = Date.now(), initial = false) {
    prunePoints(card, now);
    card.chart.setOption(initial ? chartOption(card, now) : chartUpdateOption(card, now), { notMerge: false, lazyUpdate: true, silent: true });
    updateFeedState(card, now);
  }

  function updateChartTheme(card) {
    const theme = chartTheme();
    card.chart.setOption({
      tooltip: { backgroundColor: theme.tooltipBackground, borderColor: theme.tooltipBorder, textStyle: { color: theme.tooltipText } },
      xAxis: { axisLine: { lineStyle: { color: theme.line } }, axisLabel: { color: theme.axis }, splitLine: { lineStyle: { color: theme.grid } } },
      yAxis: { nameTextStyle: { color: theme.axis }, axisLabel: { color: theme.axis }, splitLine: { lineStyle: { color: theme.grid } } },
      visualMap: { pieces: statePieces(theme) },
    }, { notMerge: false, lazyUpdate: true, silent: true });
  }

  function scheduleChartResize(card) {
    window.requestAnimationFrame(() => card.chart.resize());
  }

  liveGrid.querySelectorAll("[data-monitor-card]").forEach((element) => {
    const initial = parseSeries(element).map((point) => ({
      id: Number(point.id), time: Date.parse(point.at), latency: point.latency == null ? null : Number(point.latency), status: point.status,
    })).filter((point) => Number.isFinite(point.time));
    const chartElement = element.querySelector("[data-monitor-card-chart]");
    const id = Number(element.dataset.monitorCard);
    const card = {
      id, element, chart: window.echarts.init(chartElement, null, { renderer: "canvas" }), points: initial,
      seen: new Set(initial.map((point) => point.id)), enabled: element.dataset.monitorEnabled === "true",
      interval: Number(element.dataset.monitorInterval || 60), warning: Number(element.dataset.monitorWarning || 100),
      critical: Number(element.dataset.monitorCritical || 250),
      lastChecked: initial.length ? initial[initial.length - 1].time : null,
      incidentStart: null,
    };
    cards.set(id, card);
    renderCard(card, Date.now(), true);
    scheduleChartResize(card);
  });
  const resizeObservers = [];
  if (window.ResizeObserver) {
    cards.forEach((card) => {
      const chartShell = card.element.querySelector(".monitor-card-chart-shell");
      const observer = new ResizeObserver(() => scheduleChartResize(card));
      observer.observe(chartShell);
      resizeObservers.push(observer);
    });
  }

  function setText(selector, value) {
    const element = document.querySelector(selector);
    if (element) element.textContent = value;
  }

  function updateSummary(summary) {
    setText('[data-monitor-summary="total"]', summary.total);
    setText('[data-monitor-summary="up_count"]', summary.up_count);
    setText('[data-monitor-summary="warning_count"]', summary.warning_count);
    setText('[data-monitor-summary="critical_count"]', summary.critical_count);
    setText('[data-monitor-summary="down_count"]', summary.down_count);
    setText('[data-monitor-summary="paused_count"]', summary.paused_count);
    setText('[data-monitor-summary="active_incidents"]', summary.active_incidents);
    setText('[data-monitor-summary="average_latency"]', formatLatency(summary.average_latency));
    setText('[data-monitor-summary="availability_24h"]', summary.availability_24h == null ? "-" : `${summary.availability_24h}%`);
    setText('[data-monitor-summary="checks_per_minute"]', summary.checks_per_minute);
  }

  function updateMonitor(monitor) {
    const card = cards.get(Number(monitor.id));
    if (!card) return;
    card.enabled = monitor.enabled;
    card.interval = Math.max(Number(monitor.interval_seconds || 5), 5);
    card.lastChecked = monitor.last_checked_at ? Date.parse(monitor.last_checked_at) : card.lastChecked;
    card.incidentStart = monitor.incident_started_at ? Date.parse(monitor.incident_started_at) : null;
    card.element.dataset.monitorEnabled = String(monitor.enabled);
    card.element.dataset.monitorInterval = String(card.interval);
    const state = monitor.enabled ? (monitor.status || "unknown") : "paused";
    const previousState = card.element.dataset.monitorState || "unknown";
    card.element.dataset.monitorState = state;
    card.element.dataset.state = state;
    if (state !== previousState) {
      Array.from(card.element.classList).filter((name) => name.startsWith("state-")).forEach((name) => card.element.classList.remove(name));
      card.element.classList.add(`state-${state}`);
      card.element.classList.remove("monitor-state-changed", "monitor-offline-attention");
      void card.element.offsetWidth;
      card.element.classList.add("monitor-state-changed");
      if (state === "offline") card.element.classList.add("monitor-offline-attention");
      window.setTimeout(() => card.element.classList.remove("monitor-state-changed", "monitor-offline-attention"), 700);
    }
    const status = card.element.querySelector("[data-monitor-status]");
    if (status) {
      status.className = `status-pill ${state}`;
      status.textContent = state.charAt(0).toUpperCase() + state.slice(1);
    }
    const reason = card.element.querySelector("[data-monitor-state-reason]");
    if (reason) reason.textContent = monitor.state_reason || (state === "unknown" ? "Awaiting first check" : "");
    const current = card.element.querySelector("[data-monitor-current]");
    const average = card.element.querySelector("[data-monitor-average]");
    const availability = card.element.querySelector("[data-monitor-availability]");
    const lastResult = card.element.querySelector("[data-monitor-last-result]");
    if (current) current.textContent = monitor.latency_ms == null && state === "offline" ? "Unavailable" : formatLiveLatency(monitor.latency_ms);
    if (average) average.textContent = formatLatency(monitor.average_latency_ms);
    if (availability) availability.textContent = monitor.availability == null ? "-" : `${monitor.availability}%`;
    if (lastResult && monitor.last_checked_at) {
      lastResult.dataset.utcTime = monitor.last_checked_at;
      lastResult.textContent = relativeAge(Date.parse(monitor.last_checked_at));
    }
  }

  function relativeAge(value) {
    if (!Number.isFinite(value)) return "never";
    const seconds = Math.max(0, Math.floor((Date.now() - value) / 1000));
    if (seconds < 2) return "just now";
    if (seconds < 60) return `${seconds} seconds ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
    return `${Math.floor(seconds / 3600)} hours ago`;
  }

  function appendObservation(observation) {
    const card = cards.get(Number(observation.monitor_id));
    if (!card || card.seen.has(Number(observation.id))) return;
    const time = Date.parse(observation.checked_at);
    if (!Number.isFinite(time)) return;
    card.seen.add(Number(observation.id));
    card.points.push({
      id: Number(observation.id), time,
      latency: observation.latency_ms == null ? null : Number(observation.latency_ms),
      status: observation.status,
    });
    card.points.sort((left, right) => left.time - right.time);
    card.lastChecked = time;
  }

  async function pollLive() {
    if (polling || stopped || document.hidden || refreshSelect?.value === "paused") return;
    polling = true;
    activeRequest = new AbortController();
    try {
      const response = await fetch(`/networking/ip-wan-monitor/live?after=${afterId}`, {
        headers: { "X-Requested-With": "fetch" }, cache: "no-store", signal: activeRequest.signal,
      });
      if (!response.ok) throw new Error("Live feed unavailable");
      const payload = await response.json();
      feedFailed = false;
      (payload.observations || []).forEach((observation) => {
        appendObservation(observation);
        afterId = Math.max(afterId, Number(observation.id) || 0);
      });
      (payload.monitors || []).forEach(updateMonitor);
      updateSummary(payload.summary || {});
      cards.forEach((card) => renderCard(card));
      if (payload.has_more) {
        polling = false;
        activeRequest = null;
        await pollLive();
        return;
      }
    } catch (error) {
      if (error.name !== "AbortError") {
        feedFailed = true;
        cards.forEach((card) => updateFeedState(card, Date.now()));
      }
    } finally {
      polling = false;
      activeRequest = null;
    }
  }

  function collectionRatePayload(mode) {
    const data = new FormData();
    data.set("mode", mode);
    data.set("client_id", clientId);
    data.set("csrf_token", refreshSelect?.dataset.monitorCsrf || "");
    return data;
  }

  async function renewOverride(mode = refreshSelect?.value || "paused") {
    if (!refreshSelect) return;
    const response = await fetch("/networking/ip-wan-monitor/collection-rate", {
      method: "POST", body: collectionRatePayload(mode), cache: "no-store",
    });
    if (!response.ok) throw new Error("Unable to update the active check rate");
  }

  function releaseOverride() {
    if (!refreshSelect) return;
    window.navigator.sendBeacon(
      "/networking/ip-wan-monitor/collection-rate",
      collectionRatePayload("paused"),
    );
  }

  function clearTimers() {
    window.clearTimeout(pollTimer);
    window.clearInterval(clockTimer);
    window.clearInterval(leaseTimer);
    window.cancelAnimationFrame(traceFrame);
    pollTimer = null;
    clockTimer = null;
    leaseTimer = null;
    traceFrame = null;
    activeRequest?.abort();
  }

  function schedulePoll(immediate = false) {
    window.clearTimeout(pollTimer);
    if (stopped || document.hidden || refreshSelect?.value === "paused") return;
    const delay = pollDelays[refreshSelect?.value] || pollDelays.live;
    pollTimer = window.setTimeout(() => {
      schedulePoll(false);
      void pollLive();
    }, immediate ? 0 : delay);
  }

  function drawLiveTrace(frameTime) {
    if (stopped || document.hidden) {
      traceFrame = null;
      return;
    }
    if (frameTime - lastTraceDraw >= 100) {
      const now = Date.now();
      cards.forEach((card) => {
        prunePoints(card, now);
        card.chart.setOption(chartUpdateOption(card, now), { notMerge: false, lazyUpdate: true, silent: true });
      });
      lastTraceDraw = frameTime;
    }
    traceFrame = window.requestAnimationFrame(drawLiveTrace);
  }

  function startFeed(immediate = false) {
    clearTimers();
    cards.forEach((card) => renderCard(card));
    if (document.hidden || stopped) return;
    lastTraceDraw = 0;
    traceFrame = window.requestAnimationFrame(drawLiveTrace);
    renewOverride().catch(() => {});
    leaseTimer = window.setInterval(() => renewOverride().catch(() => {}), 10000);
    clockTimer = window.setInterval(() => {
      const now = Date.now();
      cards.forEach((card) => {
        const lastResult = card.element.querySelector("[data-monitor-last-result]");
        if (lastResult && card.lastChecked) lastResult.textContent = relativeAge(card.lastChecked);
        updateFeedState(card, now);
      });
    }, 1000);
    schedulePoll(immediate);
  }

  container.addEventListener("submit", async (event) => {
    const form = event.target.closest(".monitor-refresh-form");
    if (!form) return;
    event.preventDefault();
    const button = form.querySelector("button");
    if (button) { button.disabled = true; button.classList.add("spinning"); }
    try {
      const response = await fetch(form.action, { method: "POST", body: new FormData(form), cache: "no-store" });
      if (response.ok) await pollLive();
    } finally {
      if (button) { button.disabled = false; button.classList.remove("spinning"); }
    }
  });

  const savedMode = window.sessionStorage.getItem(storageKey);
  if (refreshSelect && Object.keys(pollDelays).includes(savedMode)) refreshSelect.value = savedMode;
  refreshSelect?.addEventListener("change", () => {
    window.sessionStorage.setItem(storageKey, refreshSelect.value);
    startFeed(true);
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      clearTimers();
      releaseOverride();
    }
    else {
      startFeed(true);
    }
  });
  const themeObserver = new MutationObserver((mutations) => {
    if (mutations.some((mutation) => mutation.attributeName === "data-kaya-theme")) {
      cards.forEach(updateChartTheme);
    }
  });
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-kaya-theme"] });
  window.addEventListener("resize", () => cards.forEach(scheduleChartResize));
  window.addEventListener("pagehide", () => {
    stopped = true;
    clearTimers();
    releaseOverride();
    themeObserver.disconnect();
    resizeObservers.forEach((observer) => observer.disconnect());
    cards.forEach((card) => card.chart.dispose());
  });
  startFeed(false);
})();
