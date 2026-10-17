(() => {
  // Asset profile history charts: every [data-asset-history-chart] element is a left-to-right
  // time-series line chart. The attribute names the chart kind; the points come from the server
  // as JSON in data-asset-history-points. Missing observations stay gaps, never zero.
  const chartElements = [...document.querySelectorAll("[data-asset-history-chart]")];
  if (!chartElements.length || !window.echarts) return;

  const cssToken = (element, name, fallback) => (getComputedStyle(element).getPropertyValue(name) || "").trim() || fallback;
  const finite = (value) => value != null && Number.isFinite(Number(value));
  const formatBytes = (value) => {
    if (!finite(value)) return "No data";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let number = Number(value);
    let index = 0;
    while (number >= 1024 && index < units.length - 1) { number /= 1024; index += 1; }
    return `${number.toFixed(number >= 100 || index === 0 ? 0 : 1)} ${units[index]}`;
  };
  const formatCount = (value) => (finite(value) ? Number(value).toLocaleString() : "No data");
  const formatPercent = (value) => (finite(value) ? `${Number(value)}%` : "No data");
  const formatMs = (value) => (finite(value) ? `${Number(value)} ms` : "No data");

  const palette = (element) => ({
    primary: cssToken(element, "--kaya-orange", "#ff8a00"),
    secondary: "#2dd4bf",
    good: cssToken(element, "--kaya-success", "#22c55e"),
    bad: cssToken(element, "--kaya-danger", "#ef4444"),
    muted: cssToken(element, "--muted", "#9ca3af"),
    grid: cssToken(element, "--kaya-border-soft", "rgba(148,163,184,.16)"),
    line: cssToken(element, "--kaya-border", "#2a303a"),
    panel: cssToken(element, "--panel", "#14171d"),
    text: cssToken(element, "--text", "#f5f5f2"),
  });

  // Chart kinds: which point fields become lines, their colours and value formatting.
  const kinds = {
    traffic: {
      yName: "Volume",
      axes: [{ formatter: formatBytes }],
      series: (colours) => [
        { name: "Download", field: "download_bytes", color: colours.primary, formatter: formatBytes },
        { name: "Upload", field: "upload_bytes", color: colours.secondary, formatter: formatBytes },
      ],
    },
    dns: {
      yName: "Queries",
      axes: [{ formatter: formatCount, minInterval: 1 }],
      series: (colours) => [
        { name: "Queries", field: "queries", color: colours.primary, formatter: formatCount },
        { name: "Blocked", field: "blocked", color: colours.bad, formatter: formatCount },
      ],
    },
    uptime: {
      yName: "Availability",
      axes: [{ formatter: formatPercent, min: 0, max: 100 }, { name: "Latency", formatter: formatMs }],
      series: (colours) => [
        { name: "Availability", field: "availability", color: colours.good, formatter: formatPercent, area: false },
        { name: "Latency", field: "latency_ms", color: colours.primary, formatter: formatMs, axis: 1, area: false },
      ],
    },
  };

  const valueAxis = (colours, axis, index, name) => ({
    type: "value",
    name: index === 0 ? name : axis.name,
    nameLocation: "middle",
    nameGap: index === 0 ? 48 : 44,
    nameTextStyle: { color: colours.muted, fontSize: 11 },
    min: axis.min,
    max: axis.max,
    minInterval: axis.minInterval,
    axisLabel: { color: colours.muted, fontSize: 11, formatter: axis.formatter },
    splitLine: { show: index === 0, lineStyle: { color: colours.grid } },
  });

  const mount = (element) => {
    const kind = kinds[element.dataset.assetHistoryChart];
    if (!kind) return;
    let points;
    try {
      points = JSON.parse(element.dataset.assetHistoryPoints || "[]");
    } catch (_) {
      points = [];
    }
    if (!Array.isArray(points) || !points.length) return;

    const chart = window.echarts.init(element, null, { renderer: "canvas" });
    const render = () => {
      if (!element.clientWidth) return;
      const colours = palette(element);
      const series = kind.series(colours);
      const dualAxis = kind.axes.length > 1;
      chart.setOption({
        animation: false,
        color: series.map((item) => item.color),
        tooltip: {
          trigger: "axis",
          backgroundColor: colours.panel,
          borderColor: colours.line,
          textStyle: { color: colours.text, fontSize: 12 },
          axisPointer: { type: "line", lineStyle: { color: colours.muted, type: "dashed" } },
        },
        legend: { bottom: 0, itemWidth: 12, itemHeight: 8, textStyle: { color: colours.muted, fontSize: 11 } },
        grid: { left: 68, right: dualAxis ? 60 : 14, top: 14, bottom: 48, containLabel: false },
        xAxis: {
          type: "time",
          axisLine: { lineStyle: { color: colours.line } },
          axisTick: { show: false },
          axisLabel: { color: colours.muted, fontSize: 11, hideOverlap: true },
          splitLine: { show: false },
        },
        yAxis: kind.axes.map((axis, index) => valueAxis(colours, axis, index, kind.yName)),
        series: series.map((item) => ({
          name: item.name,
          type: "line",
          yAxisIndex: item.axis || 0,
          connectNulls: false,
          showSymbol: points.length === 1,
          smooth: 0.25,
          lineStyle: { width: 2, color: item.color },
          itemStyle: { color: item.color },
          areaStyle: item.area === false ? undefined : { color: item.color, opacity: 0.12 },
          emphasis: { focus: "series" },
          tooltip: { valueFormatter: item.formatter },
          data: points.map((point) => [point.at, finite(point[item.field]) ? Number(point[item.field]) : null]),
        })),
      }, true);
    };

    render();
    // The History tab starts hidden, so the first real render happens when it gains a size.
    const resizeObserver = new ResizeObserver(() => { render(); chart.resize(); });
    resizeObserver.observe(element);
    const themeObserver = new MutationObserver(render);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-kaya-theme"] });
    window.addEventListener("beforeunload", () => { resizeObserver.disconnect(); themeObserver.disconnect(); chart.dispose(); }, { once: true });
  };

  chartElements.forEach(mount);
})();
