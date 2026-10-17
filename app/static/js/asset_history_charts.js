(() => {
  const chartElement = document.querySelector("[data-asset-traffic-chart]");
  if (!chartElement || !window.echarts) return;

  let history;
  try {
    history = JSON.parse(chartElement.dataset.assetTrafficChart || "[]");
  } catch (_) {
    history = [];
  }
  if (!Array.isArray(history) || !history.length) return;

  const cssToken = (name, fallback) => (getComputedStyle(chartElement).getPropertyValue(name) || "").trim() || fallback;
  const formatBytes = (value) => {
    if (value == null || !Number.isFinite(Number(value))) return "No data";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let number = Number(value);
    let index = 0;
    while (number >= 1024 && index < units.length - 1) { number /= 1024; index += 1; }
    return `${number.toFixed(number >= 100 || index === 0 ? 0 : 1)} ${units[index]}`;
  };
  const theme = () => ({
    download: cssToken("--traffic-download", "#ff8a00"),
    upload: cssToken("--traffic-upload", "#2dd4bf"),
    muted: cssToken("--muted", "#9ca3af"),
    grid: cssToken("--traffic-line-soft", "rgba(148,163,184,.16)"),
    line: cssToken("--traffic-line", "#2a303a"),
    panel: cssToken("--panel", "#14171d"),
    text: cssToken("--text", "#f5f5f2"),
  });
  const areaFill = (colour) => new window.echarts.graphic.LinearGradient(0, 0, 0, 1, [
    { offset: 0, color: `${colour}40` },
    { offset: 1, color: `${colour}00` },
  ]);
  const render = () => {
    if (!chartElement.clientWidth) return;
    const colours = theme();
    chart.setOption({
      animation: false,
      color: [colours.download, colours.upload],
      tooltip: {
        trigger: "axis",
        backgroundColor: colours.panel,
        borderColor: colours.line,
        textStyle: { color: colours.text, fontSize: 12 },
        axisPointer: { type: "line", lineStyle: { color: colours.muted, type: "dashed" } },
        valueFormatter: formatBytes,
      },
      legend: { bottom: 0, itemWidth: 12, itemHeight: 8, textStyle: { color: colours.muted, fontSize: 11 } },
      grid: { left: 68, right: 14, top: 14, bottom: 42, containLabel: false },
      xAxis: {
        type: "time",
        name: "Time",
        nameLocation: "middle",
        nameGap: 26,
        nameTextStyle: { color: colours.muted, fontSize: 11 },
        axisLine: { lineStyle: { color: colours.line } },
        axisTick: { show: false },
        axisLabel: { color: colours.muted, fontSize: 11, hideOverlap: true },
        splitLine: { show: false },
      },
      yAxis: {
        type: "value",
        name: "Volume",
        nameLocation: "middle",
        nameGap: 48,
        nameTextStyle: { color: colours.muted, fontSize: 11 },
        axisLabel: { color: colours.muted, fontSize: 11, formatter: formatBytes },
        splitLine: { lineStyle: { color: colours.grid } },
      },
      series: [
        { name: "Download", type: "line", connectNulls: false, showSymbol: false, smooth: 0.25, lineStyle: { width: 2, color: colours.download }, itemStyle: { color: colours.download }, areaStyle: { color: areaFill(colours.download) }, emphasis: { focus: "series" }, data: history.map((item) => [item.at, item.download_bytes ?? null]) },
        { name: "Upload", type: "line", connectNulls: false, showSymbol: false, smooth: 0.25, lineStyle: { width: 2, color: colours.upload }, itemStyle: { color: colours.upload }, areaStyle: { color: areaFill(colours.upload) }, emphasis: { focus: "series" }, data: history.map((item) => [item.at, item.upload_bytes ?? null]) },
      ],
    }, true);
  };

  const chart = window.echarts.init(chartElement, null, { renderer: "canvas" });
  render();
  const resizeObserver = new ResizeObserver(() => { render(); chart.resize(); });
  resizeObserver.observe(chartElement);
  const themeObserver = new MutationObserver(render);
  themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-kaya-theme"] });
  window.addEventListener("beforeunload", () => { resizeObserver.disconnect(); themeObserver.disconnect(); chart.dispose(); }, { once: true });
})();
