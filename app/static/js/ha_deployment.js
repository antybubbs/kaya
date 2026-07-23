(() => {
  const root = document.querySelector("[data-ha-deployment-live]");
  if (!root) return;

  const endpoint = root.dataset.endpoint;
  const liveStatus = root.querySelector("[data-ha-live-status]");
  const liveLabel = root.querySelector("[data-ha-live-label]");
  let polling = false;
  let timer = null;

  const titleCase = (value) => String(value || "Unknown")
    .toLowerCase()
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());

  function setText(container, selector, value) {
    const element = container.querySelector(selector);
    if (element) element.textContent = value;
  }

  function parseServerTime(value) {
    if (!value) return null;
    const explicitZone = /(?:Z|[+-]\d\d:\d\d)$/.test(value);
    const parsed = new Date(explicitZone ? value : `${value}Z`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  function heartbeatAge(nodes) {
    const ages = nodes.map((node) => parseServerTime(node.last_heartbeat_at))
      .filter(Boolean)
      .map((time) => Math.max(0, Date.now() - time.getTime()));
    return ages.length === nodes.length && ages.length ? Math.max(...ages) : null;
  }

  function ageLabel(milliseconds) {
    if (milliseconds === null) return "heartbeat unavailable";
    const seconds = Math.floor(milliseconds / 1000);
    if (seconds < 5) return "heartbeat just now";
    if (seconds < 60) return `heartbeat ${seconds}s ago`;
    return `heartbeat ${Math.floor(seconds / 60)}m ago`;
  }

  function updateLiveStatus(nodes) {
    const age = heartbeatAge(nodes);
    liveStatus?.classList.remove("is-connecting", "is-live", "is-delayed", "is-error");
    const current = age !== null && age <= 30000;
    liveStatus?.classList.add(current ? "is-live" : "is-delayed");
    if (liveLabel) liveLabel.textContent = `${current ? "Live" : "Delayed"} · ${ageLabel(age)}`;
  }

  function updateNode(node) {
    const card = root.querySelector(`[data-ha-node-id="${CSS.escape(node.public_id)}"]`);
    if (!card) return;
    setText(card, "[data-ha-node-name]", node.display_name);
    setText(card, "[data-ha-interface]", node.network_interface || "Not set");
    setText(card, "[data-ha-priority]", node.vrrp_priority || "Not assigned");
    setText(card, "[data-ha-runtime]", titleCase(node.keepalived_runtime_state));
    setText(card, "[data-ha-vip]", node.vip_owned ? "Owned" : "Not owned");
    setText(card, "[data-ha-checksum]", node.keepalived_config_checksum ? node.keepalived_config_checksum.slice(0, 12) : "Not reported");

    const state = card.querySelector("[data-ha-keepalived-state]");
    if (state) {
      state.textContent = titleCase(node.keepalived_status);
      state.classList.remove("is-online", "is-pending", "is-revoked");
      state.classList.add(node.keepalived_status === "DEPLOYED" ? "is-online" : (node.keepalived_status === "ERROR" ? "is-revoked" : "is-pending"));
    }

    const diagnostic = card.querySelector("[data-ha-diagnostic]");
    const message = card.querySelector("[data-ha-error-message]");
    if (diagnostic) diagnostic.hidden = !node.keepalived_last_error;
    if (message) message.textContent = node.keepalived_last_error || "";
  }

  function updateSummary(cluster) {
    setText(root, "[data-ha-cluster-status]", titleCase(cluster.keepalived_status));
    setText(root, "[data-ha-generation]", cluster.keepalived_generation);
    const summary = root.querySelector("[data-ha-vip-summary]");
    if (!summary) return;
    const owners = cluster.nodes.filter((node) => node.vip_owned);
    const badge = document.createElement("span");
    badge.className = `ha-readiness ${owners.length === 1 ? "ha-readiness--ready" : (owners.length > 1 ? "ha-readiness--blocked" : "ha-readiness--warning")}`;
    badge.textContent = owners.length === 1 ? owners[0].display_name : (owners.length > 1 ? "Unsafe: multiple owners" : "No owner reported");
    summary.replaceChildren(badge);
  }

  async function refresh() {
    if (polling || document.hidden) return;
    polling = true;
    try {
      const response = await fetch(endpoint, { headers: { "X-Requested-With": "fetch" }, cache: "no-store" });
      if (!response.ok) throw new Error("status request failed");
      const cluster = await response.json();
      cluster.nodes.forEach(updateNode);
      updateSummary(cluster);
      updateLiveStatus(cluster.nodes);
    } catch (_) {
      liveStatus?.classList.remove("is-connecting", "is-live", "is-delayed");
      liveStatus?.classList.add("is-error");
      if (liveLabel) liveLabel.textContent = "Live updates unavailable";
    } finally {
      polling = false;
    }
  }

  function schedule(immediate = false) {
    window.clearTimeout(timer);
    if (document.hidden) return;
    timer = window.setTimeout(async () => {
      await refresh();
      schedule(false);
    }, immediate ? 0 : 5000);
  }

  document.addEventListener("visibilitychange", () => schedule(!document.hidden));
  schedule(true);
})();
