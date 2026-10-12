(() => {
  const target = document.querySelector("[data-flow-collector-diagnostics]");
  if (!target) return;

  let sourcesByName = new Map();
  const text = (value, fallback = "unknown") => value == null || value === "" ? fallback : String(value);

  const renderBinding = () => {
    const bind = Array.from(target.querySelectorAll(".traffic-diagnostic-grid > div")).find((item) => item.querySelector("span")?.textContent === "Bind");
    if (!bind) return;
    bind.querySelector("span").textContent = "Internal bind";
    const value = bind.querySelector("strong")?.textContent || "unknown";
    if (target.querySelector("[data-published-binding]")) return;
    const published = document.createElement("div");
    published.dataset.publishedBinding = "true";
    const label = document.createElement("span");
    label.className = "muted";
    label.textContent = "Published host";
    const valueNode = document.createElement("strong");
    valueNode.textContent = "Unknown — verify with docker port";
    published.append(label, valueNode);
    bind.parentElement.appendChild(published);
    const guidance = document.createElement("p");
    guidance.className = "muted";
    guidance.textContent = `Kaya reports the process-local listener (${value}). Docker's published host address is not available from application telemetry; verify it with docker port.`;
    target.insertBefore(guidance, target.querySelector(".traffic-diagnostic-list"));
  };

  const addCell = (row, value) => {
    const cell = document.createElement("td");
    cell.textContent = text(value);
    row.appendChild(cell);
  };

  const renderLifecycle = (article, source) => {
    if (article.dataset.templateLifecycle) return;
    article.dataset.templateLifecycle = "true";
    const events = Array.isArray(source.template_lifecycle) ? source.template_lifecycle.slice(-32) : [];
    const details = document.createElement("details");
    details.className = "traffic-template-lifecycle";
    const summary = document.createElement("summary");
    summary.textContent = `Template lifecycle (${events.length})`;
    details.appendChild(summary);
    if (!events.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "No lifecycle events persisted since the collector update.";
      details.appendChild(empty);
    } else {
      const wrapper = document.createElement("div");
      wrapper.className = "traffic-template-lifecycle-table";
      const table = document.createElement("table");
      const header = document.createElement("tr");
      ["Timestamp", "Template", "Exporter", "Source", "Event", "Reason"].forEach((label) => addCell(header, label));
      table.appendChild(header);
      events.slice().reverse().forEach((event) => {
        const row = document.createElement("tr");
        addCell(row, event.at);
        addCell(row, event.template_id);
        addCell(row, event.exporter_identity);
        addCell(row, event.source_id);
        addCell(row, event.status);
        addCell(row, event.reason);
        table.appendChild(row);
      });
      wrapper.appendChild(table);
      details.appendChild(wrapper);
    }
    article.appendChild(details);
  };

  const renderTemplateDetails = () => {
    if (!sourcesByName.size) return;
    target.querySelectorAll(".traffic-diagnostic-list article").forEach((article) => {
      const name = article.querySelector("strong")?.textContent || "";
      const source = sourcesByName.get(name);
      if (!source) return;
      if (!article.dataset.templateDetails) {
        const detail = document.createElement("span");
        detail.textContent = `Last template: ${source.last_unknown_template_id == null ? "none" : `${source.last_unknown_template_id} · ${source.last_template_error_category || "unknown"} · exporter ${source.last_unknown_template_exporter || "unknown"} · source ${source.last_unknown_template_source_id ?? "unknown"}`}`;
        article.querySelector("div:last-child")?.appendChild(detail);
        article.dataset.templateDetails = "true";
      }
      renderLifecycle(article, source);
    });
  };

  const loadTemplateDetails = async () => {
    try {
      const response = await fetch("/networking/ip-wan-monitor/traffic/diagnostics", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      if (!response.ok) return;
      const payload = await response.json();
      sourcesByName = new Map((payload.flow_collector?.sources || []).map((source) => [String(source.name), source]));
      renderTemplateDetails();
    } catch {
      // The primary diagnostics renderer continues to show collector counters.
    }
  };

  const observer = new MutationObserver(() => {
    renderBinding();
    renderTemplateDetails();
  });
  observer.observe(target, { childList: true, subtree: true });
  renderBinding();
  loadTemplateDetails();
})();
