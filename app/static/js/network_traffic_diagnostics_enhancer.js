(() => {
  const target = document.querySelector("[data-flow-collector-diagnostics]");
  if (!target) return;

  const renderBindingAndTemplateDetails = () => {
    const bind = Array.from(target.querySelectorAll(".traffic-diagnostic-grid > div")).find((item) => item.querySelector("span")?.textContent === "Bind");
    if (bind) {
      bind.querySelector("span").textContent = "Internal bind";
      const value = bind.querySelector("strong")?.textContent || "unknown";
      if (!target.querySelector("[data-published-binding]")) {
        const published = document.createElement("div");
        published.dataset.publishedBinding = "true";
        published.innerHTML = "<span class=\"muted\">Published host</span><strong>Unknown — verify with docker port</strong>";
        bind.parentElement.appendChild(published);
        const guidance = document.createElement("p");
        guidance.className = "muted";
        guidance.textContent = `Kaya reports the process-local listener (${value}). Docker's published host address is not available from application telemetry; verify it with docker port.`;
        target.insertBefore(guidance, target.querySelector(".traffic-diagnostic-list"));
      }
    }
  };

  const addTemplateDetails = async () => {
    if (target.dataset.templateDetailsLoaded) return;
    target.dataset.templateDetailsLoaded = "pending";
    try {
      const response = await fetch("/networking/ip-wan-monitor/traffic/diagnostics", { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } });
      if (!response.ok) return;
      const payload = await response.json();
      const details = new Map((payload.flow_collector?.sources || []).map((source) => [String(source.name), source]));
      target.querySelectorAll(".traffic-diagnostic-list article").forEach((article) => {
        const name = article.querySelector("strong")?.textContent || "";
        const source = details.get(name);
        if (!source || article.dataset.templateDetails) return;
        const detail = document.createElement("span");
        detail.textContent = `Last template: ${source.last_unknown_template_id == null ? "none" : `${source.last_unknown_template_id} · ${source.last_template_error_category || "unknown"} · exporter ${source.last_unknown_template_exporter || "unknown"} · source ${source.last_unknown_template_source_id ?? "unknown"}`}`;
        article.querySelector("div:last-child")?.appendChild(detail);
        article.dataset.templateDetails = "true";
      });
      target.dataset.templateDetailsLoaded = "done";
    } catch {
      delete target.dataset.templateDetailsLoaded;
    }
  };

  const observer = new MutationObserver(renderBindingAndTemplateDetails);
  observer.observe(target, { childList: true, subtree: true });
  renderBindingAndTemplateDetails();
  addTemplateDetails();
})();
