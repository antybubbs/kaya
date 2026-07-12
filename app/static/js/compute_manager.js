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
    } catch (_) {
      age.textContent = "connection interrupted";
    }
  };

  refresh();
  setInterval(refresh, 5000);
  setInterval(renderAge, 1000);
})();
