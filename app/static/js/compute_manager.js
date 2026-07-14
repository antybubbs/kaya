(() => {
  const platform = document.querySelector("[data-compute-platform]");

  const togglePlatform = () => {
    const value = platform?.value;

    document.querySelectorAll("[data-proxmox-field]").forEach((field) => {
      field.hidden = value !== "proxmox";
    });

    document.querySelectorAll("[data-docker-agent-field]").forEach((field) => {
      field.hidden = value !== "docker_agent";
    });
  };

  platform?.addEventListener("change", togglePlatform);
  togglePlatform();

  const dnsAge = document.querySelector("[data-dns-summary-age]");
  const renderDnsAge = () => {
    if (!dnsAge) return;
    const updated = new Date(dnsAge.dataset.dnsSummaryAge || "");
    if (Number.isNaN(updated.getTime())) return;
    const seconds = Math.max(0, Math.floor((Date.now() - updated.getTime()) / 1000));
    const relative = seconds < 60
      ? `${seconds} second${seconds === 1 ? "" : "s"}`
      : seconds < 3600
        ? `${Math.floor(seconds / 60)} minute${Math.floor(seconds / 60) === 1 ? "" : "s"}`
        : `${Math.floor(seconds / 3600)} hour${Math.floor(seconds / 3600) === 1 ? "" : "s"}`;
    dnsAge.textContent = `Updated ${relative} ago`;
    dnsAge.title = updated.toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" });
  };
  renderDnsAge();
  if (dnsAge) setInterval(renderDnsAge, 30000);

  const age = document.querySelector("[data-live-age]");
  if (!age) return;

  let lastUpdate = null;

  const renderAge = () => {
    if (!lastUpdate) return;

    const seconds = Math.max(0, Math.floor((Date.now() - lastUpdate) / 1000));
    age.textContent = `updated ${seconds}s ago`;
  };

  const displayValue = (value) => {
    if (Array.isArray(value)) return value.length;
    if (value && typeof value === "object") return value.count ?? 0;
    return value ?? 0;
  };

  const refresh = async () => {
    try {
      const response = await fetch("/infrastructure/vm-docker-manager/api/summary", {
        headers: { Accept: "application/json" },
      });

      if (!response.ok) return;

  const data = await response.json();
      // Refresh DNS dashboard summary
  const dnsResponse = await fetch("/dashboard/api/dns-summary", {
    headers: { Accept: "application/json" },
  });

  let dns = null;

    if (dnsResponse.ok) {
    dns = await dnsResponse.json();
    }
      lastUpdate = Date.now();
      
      document.querySelectorAll("[data-summary]").forEach((el) => {
        const value = data[el.dataset.summary];

        if (value !== undefined) {
          el.textContent = displayValue(value);
        }
      });

      document.querySelectorAll("[data-resource]").forEach((el) => {
        const value = data[el.dataset.resource];
        el.textContent = value == null ? "-" : `${value}%`;
      });

      document.querySelectorAll("[data-resource-bar]").forEach((el) => {
        const value = data[el.dataset.resourceBar] || 0;
        el.style.width = `${Math.min(100, value)}%`;
      });

      (data.hosts || []).forEach((host) => {
        const card = document.querySelector(`[data-host-id="${host.id}"]`);
        if (!card) return;

        card.className = `compute-host-card status-${host.status}`;

        const set = (selector, value) => {
          const el = card.querySelector(selector);
          if (el) {
            el.textContent = value == null ? "-" : `${value}%`;
          }
        };

        set("[data-host-cpu]", host.cpu);
        set("[data-host-memory]", host.memory);
        set("[data-host-storage]", host.storage);
      });
      
      if (dns) {

    const status = document.querySelector(".dashboard-dns-status");
    if (status) {
        status.lastChild.textContent = dns.provider_status_label;
    }

    const ageElement = document.querySelector("[data-dns-summary-age]");
    if (ageElement && dns.last_updated_at) {
        ageElement.dataset.dnsSummaryAge = dns.last_updated_at;
        renderDnsAge();
    }

    const metrics = document.querySelectorAll(".dashboard-dns-metrics strong");

    if (metrics.length >= 4) {

        metrics[0].textContent =
            dns.queries_today == null
                ? "No data"
                : Number(dns.queries_today).toLocaleString();

        metrics[1].textContent =
            dns.blocked_percentage == null
                ? "Unavailable"
                : `${Number(dns.blocked_percentage).toFixed(1)}%`;

        metrics[2].textContent =
            dns.active_clients_24h ?? "No data";

        metrics[3].textContent =
            dns.attention_count;
    }
}
    } catch (_) {
      age.textContent = "connection interrupted";
    }
  };

  refresh();
  setInterval(refresh, 5000);
  setInterval(renderAge, 1000);
})();
