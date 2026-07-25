(() => {
  const root = document.querySelector("[data-ha-live-root]");
  if (!root) return;

  const title = (value) => String(value ?? "Unknown").toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  const yesNo = (value, yes, no, unknown = "Unknown") => value === true ? yes : value === false ? no : unknown;
  const localDate = (value) => {
    if (!value) return "Never";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? "Unknown" : parsed.toLocaleString([], {dateStyle: "medium", timeStyle: "medium"});
  };
  const relative = (value) => {
    if (!value) return "Never";
    const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
    if (seconds < 2) return "Just now";
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    return localDate(value);
  };
  const valueFor = (object, key) => {
    const value = object?.[key];
    if (key.endsWith("_at")) return localDate(value);
    if (key === "status" || key.endsWith("_status") || key.endsWith("_role")) return title(value);
    if (key === "automatic_failover") return value ? "Enabled" : "Disabled";
    return value ?? "Not reported";
  };
  const updateFields = (scope, selector, object) => scope.querySelectorAll(selector).forEach((element) => {
    const key = element.dataset.haClusterField || element.dataset.haNodeField || element.dataset.haLeaseField || element.dataset.haFailoverField || element.dataset.haSyncField;
    element.textContent = valueFor(object, key);
  });
  const setStateClass = (element, good, warning = false) => {
    element.classList.remove("is-live", "is-delayed", "is-error", "is-online", "is-pending", "is-revoked");
    element.classList.add(good ? "is-online" : warning ? "is-pending" : "is-revoked");
  };
  const dhcpEvidenceCurrent = (node) => node.heartbeat_current === true
    && node.dhcp_observation_status === "FRESH"
    && ["RUNNING", "STOPPED"].includes(node.dhcp_runtime_state);
  const dhcpRuntimeLabel = (node) => {
    if (!node.heartbeat_current) return "Unknown — node offline";
    if (!dhcpEvidenceCurrent(node)) return "Unknown — probe unavailable";
    return node.dhcp_runtime_state === "RUNNING" ? "Running" : "Stopped";
  };
  const updateStatusChips = (status) => document.querySelectorAll(".ha-status-chip").forEach((element) => {
    Array.from(element.classList).filter((name) => name.startsWith("is-")).forEach((name) => element.classList.remove(name));
    element.classList.add(`is-${String(status || "unknown").toLowerCase().replaceAll("_", "-")}`);
  });

  function updateNodes(nodes) {
    nodes.forEach((node) => {
      document.querySelectorAll(`[data-ha-node-id="${CSS.escape(node.id)}"]`).forEach((card) => {
        const current = node.heartbeat_current === true;
        updateFields(card, "[data-ha-node-field]", node);
        card.querySelectorAll("[data-ha-node-role]").forEach((element) => { element.textContent = node.is_preferred ? "Preferred" : title(node.desired_role); });
        card.querySelectorAll("[data-ha-deployment-role]").forEach((element) => { element.textContent = node.desired_role === "ACTIVE" ? "Preferred" : "Backup"; });
        card.querySelectorAll("[data-ha-agent-version-status]").forEach((element) => {
          element.textContent = node.agent_version_status;
          element.classList.toggle("is-current", node.agent_version_status === "Up to date");
          element.classList.toggle("is-update", node.agent_version_status !== "Up to date");
        });
        card.querySelectorAll('[data-ha-node-field="last_heartbeat_at"]').forEach((element) => { element.textContent = relative(node.last_heartbeat_at); });
        card.querySelectorAll('[data-ha-node-field="health_summary"]').forEach((element) => {
          const dhcp = dhcpEvidenceCurrent(node) ? (node.dhcp_runtime_state === "RUNNING" ? "DHCP running" : "DHCP stopped") : "DHCP state unknown";
          element.textContent = current ? `${yesNo(node.dns_healthy, "DNS healthy", "DNS unavailable")} · ${dhcp} · ${node.vip_owned ? "VIP owned" : "VIP standby"}` : "Telemetry delayed — waiting for this node";
        });
        card.querySelectorAll('[data-ha-node-field="observed_role"]').forEach((element) => { element.textContent = current ? title(node.observed_role) : `${title(node.observed_role)} (last report)`; });
        card.querySelectorAll('[data-ha-node-field="vip_owned"]').forEach((element) => { element.textContent = current ? (node.vip_owned ? "Owned" : "Not owned") : "Unknown — node offline"; });
        card.querySelectorAll('[data-ha-node-field="dns_healthy"]').forEach((element) => { element.textContent = current ? yesNo(node.dns_healthy, "Healthy", "Unhealthy") : "Unknown — node offline"; });
        card.querySelectorAll('[data-ha-node-field="dhcp_running"]').forEach((element) => { element.textContent = dhcpRuntimeLabel(node); });
        card.querySelectorAll('[data-ha-node-field="dhcp_configured"]').forEach((element) => { element.textContent = dhcpEvidenceCurrent(node) ? yesNo(node.dhcp_configured, "Enabled", "Disabled") : "Unknown — probe unavailable"; });
        card.querySelectorAll('[data-ha-node-field="dhcp_listener_active"]').forEach((element) => { element.textContent = dhcpEvidenceCurrent(node) ? yesNo(node.dhcp_listener_active, "Listening", "Released") : "Unknown — probe unavailable"; });
        card.querySelectorAll('[data-ha-node-field="peer_reachable"]').forEach((element) => {
          element.textContent = node.peer_icmp_probe_status === "UNAVAILABLE" ? "ICMP probe unavailable" : node.peer_reachable === true ? "Ping available" : node.peer_reachable === false ? "Ping unavailable" : "Not tested";
        });
        card.querySelectorAll("[data-ha-kaya-connection]").forEach((element) => { element.textContent = current ? "Reporting" : "Not reporting"; });
        card.querySelectorAll("[data-ha-peer-status]").forEach((element) => { element.textContent = node.peer_diagnostic?.display_label || "Not tested"; });
        card.querySelectorAll("[data-ha-peer-explanation]").forEach((element) => { element.textContent = node.peer_diagnostic?.explanation || "No ICMP ping result has been reported yet."; });
        card.querySelectorAll("[data-ha-peer-attempt]").forEach((element) => { element.textContent = localDate(node.peer_diagnostic?.last_attempt_at); });
        card.querySelectorAll("[data-ha-peer-success]").forEach((element) => { element.textContent = localDate(node.peer_diagnostic?.last_success_at); });
        card.querySelectorAll("[data-ha-peer-dns-status]").forEach((element) => { element.textContent = node.peer_diagnostic?.dns_display_label || "Not tested"; });
        card.querySelectorAll("[data-ha-peer-dns-explanation]").forEach((element) => { element.textContent = node.peer_diagnostic?.dns_explanation || "No peer DNS port result has been reported yet."; });
        card.querySelectorAll("[data-ha-peer-dns-attempt]").forEach((element) => { element.textContent = localDate(node.peer_diagnostic?.dns_last_attempt_at); });
        card.querySelectorAll("[data-ha-peer-dns-success]").forEach((element) => { element.textContent = localDate(node.peer_diagnostic?.dns_last_success_at); });
        card.querySelectorAll("[data-ha-peer-kaya-status]").forEach((element) => { element.textContent = node.peer_diagnostic?.peer_kaya_display_label || "Not reported"; });
        card.querySelectorAll("[data-ha-peer-kaya-explanation]").forEach((element) => { element.textContent = node.peer_diagnostic?.peer_kaya_explanation || "No signed peer heartbeat has been reported."; });
        card.querySelectorAll("[data-ha-peer-kaya-heartbeat]").forEach((element) => { element.textContent = localDate(node.peer_diagnostic?.peer_kaya_last_heartbeat_at); });
        const recoveryChecks = card.querySelector("[data-ha-recovery-checks]");
        if (recoveryChecks) {
          recoveryChecks.replaceChildren(...node.recovery_checks.filter((check) => check.required).map((check) => {
            const row = document.createElement("div");
            row.className = `ha-recovery-check ${check.passed ? "is-pass" : "is-waiting"}`;
            row.dataset.haRecoveryCheck = check.key;
            const icon = document.createElement("span");
            icon.setAttribute("aria-hidden", "true");
            icon.textContent = check.passed ? "✓" : "•";
            const body = document.createElement("span");
            const label = document.createElement("strong");
            label.textContent = check.label;
            const detail = document.createElement("small");
            detail.textContent = check.detail;
            body.append(label, detail);
            row.append(icon, body);
            return row;
          }));
        }
        card.querySelectorAll("[data-ha-runtime]").forEach((element) => { element.textContent = title(node.keepalived_runtime_state); });
        card.querySelectorAll("[data-ha-interface]").forEach((element) => { element.textContent = node.network_interface || "Not set"; });
        card.querySelectorAll("[data-ha-priority]").forEach((element) => { element.textContent = node.vrrp_priority || "Not assigned"; });
        card.querySelectorAll("[data-ha-vip]").forEach((element) => { element.textContent = node.vip_owned ? "Owned" : "Not owned"; });
        card.querySelectorAll("[data-ha-checksum]").forEach((element) => { element.textContent = node.keepalived_config_checksum ? node.keepalived_config_checksum.slice(0, 12) : "Not reported"; });
        const keepalivedState = card.querySelector("[data-ha-keepalived-state]");
        if (keepalivedState) { keepalivedState.textContent = title(node.keepalived_status); setStateClass(keepalivedState, node.keepalived_status === "DEPLOYED", node.keepalived_status !== "ERROR"); }
        const diagnostic = card.querySelector("[data-ha-diagnostic]");
        if (diagnostic) diagnostic.hidden = !node.keepalived_last_error;
        const diagnosticMessage = card.querySelector("[data-ha-error-message]");
        if (diagnosticMessage) diagnosticMessage.textContent = node.keepalived_last_error || "";
        const state = card.querySelector("[data-ha-node-live-state]");
        if (state) {
          state.textContent = node.service_state === "ACTIVE" ? "Active" : node.service_state === "OFFLINE" ? "Offline" : current ? "Live" : "Delayed";
          setStateClass(state, current, !current && node.service_state !== "OFFLINE");
        }
      });
    });
  }

  function updateDeploymentLiveStatus(nodes) {
    const heartbeatTimes = nodes.map((node) => node.last_heartbeat_at ? new Date(node.last_heartbeat_at).getTime() : Number.NaN);
    const validTimes = heartbeatTimes.filter(Number.isFinite);
    const oldestAgeSeconds = validTimes.length === nodes.length && validTimes.length
      ? Math.max(...validTimes.map((time) => Math.max(0, Math.floor((Date.now() - time) / 1000))))
      : null;
    const live = oldestAgeSeconds !== null && oldestAgeSeconds <= 30;
    document.querySelectorAll("[data-ha-live-status]").forEach((element) => {
      element.classList.remove("is-connecting", "is-live", "is-delayed", "is-error");
      element.classList.add(live ? "is-live" : "is-delayed");
    });
    document.querySelectorAll("[data-ha-live-label]").forEach((element) => {
      element.textContent = live
        ? `Live · latest reports within ${Math.max(1, oldestAgeSeconds)}s`
        : oldestAgeSeconds === null ? "Waiting for node reports" : `Delayed · oldest report ${oldestAgeSeconds}s ago`;
    });
  }

  function updateEvents(events) {
    const list = document.querySelector("[data-ha-event-list]");
    if (!list) return;
    if (!events.length) { list.innerHTML = '<div class="ha-inline-empty"><p>No HA events have been received.</p></div>'; return; }
    list.replaceChildren(...events.map((event) => {
      const article = document.createElement("article");
      const badge = document.createElement("span");
      badge.className = `ha-check-state ha-check-state--${["error", "critical"].includes(event.severity) ? "fail" : event.severity === "warning" ? "unknown" : "pass"}`;
      badge.textContent = title(event.severity);
      const body = document.createElement("div");
      const strong = document.createElement("strong"); strong.textContent = title(event.type);
      const paragraph = document.createElement("p"); paragraph.textContent = event.message;
      const small = document.createElement("small"); small.textContent = `${event.node} · ${localDate(event.occurred_at)}${event.acknowledged ? " · Acknowledged" : ""}`;
      body.append(strong, paragraph, small); article.append(badge, body); return article;
    }));
  }

  function updateReadiness(readiness) {
    document.querySelectorAll("[data-ha-readiness-label]").forEach((element) => {
      element.textContent = readiness.ready ? "Ready" : "Action needed";
      element.className = `ha-readiness ${readiness.ready ? "ha-readiness--ready" : "ha-readiness--warning"}`;
    });
    document.querySelectorAll("[data-ha-readiness-blockers]").forEach((list) => {
      list.replaceChildren(...readiness.blockers.map((message) => { const item = document.createElement("li"); item.textContent = message; return item; }));
      list.hidden = readiness.ready;
    });
    document.querySelectorAll("[data-ha-failover-submit]").forEach((button) => {
      button.disabled = !readiness.ready;
      button.textContent = readiness.ready ? readiness.action_label : "Handover unavailable";
    });
    document.querySelectorAll("[data-ha-failover-help]").forEach((message) => { message.hidden = readiness.ready; });
    document.querySelectorAll("[data-ha-failover-summary]").forEach((summary) => {
      summary.classList.toggle("is-disabled", !readiness.ready);
      summary.setAttribute("aria-disabled", readiness.ready ? "false" : "true");
    });
    document.querySelectorAll("[data-ha-failover-summary-label]").forEach((label) => {
      label.textContent = readiness.ready ? `${readiness.action_label} to` : "Handover unavailable";
    });
    document.querySelectorAll("[data-ha-failover-target]").forEach((input) => { input.value = readiness.target_id || ""; });
    document.querySelectorAll("[data-ha-failover-target-name]").forEach((element) => { element.textContent = readiness.target_name || "standby node"; });
  }

  function updateDeployment(deployment) {
    const blocker = document.querySelector("#deployment-blockers");
    const list = blocker?.parentElement?.querySelector(".ha-blocker-list");
    if (blocker) blocker.hidden = deployment.ready;
    if (list) {
      list.hidden = deployment.ready;
      list.replaceChildren(...deployment.blockers.map((message) => { const item = document.createElement("li"); item.textContent = message; return item; }));
    }
    const form = document.querySelector(".ha-deployment-form");
    if (form && blocker) {
      const acknowledgement = form.querySelector('[name="acknowledge_dhcp_boundary"]');
      const button = form.querySelector('button[type="submit"]');
      if (acknowledgement) acknowledgement.disabled = !deployment.ready;
      if (button) { button.disabled = !deployment.ready; button.textContent = deployment.ready ? "Deploy Keepalived" : "Resolve blockers to deploy"; }
    }
  }

  function updateTransitionProgress(failover) {
    const panel = document.querySelector("[data-ha-transition-progress]");
    if (!panel || !failover) return;
    const percent = Math.max(0, Math.min(100, Number(failover.progress_percent) || 0));
    const track = panel.querySelector('[role="progressbar"]');
    const bar = panel.querySelector("[data-ha-transition-bar]");
    if (track) track.setAttribute("aria-valuenow", String(percent));
    if (bar) bar.style.width = `${percent}%`;
    const message = panel.querySelector("[data-ha-transition-message]");
    if (message) message.textContent = failover.message || "Reconciling the transition";
    const status = panel.querySelector("[data-ha-transition-status]");
    if (status) status.textContent = title(failover.status);
    const elapsed = panel.querySelector("[data-ha-transition-elapsed]");
    if (elapsed) elapsed.textContent = `${Number(failover.elapsed_seconds) || 0}s`;
    const attempt = panel.querySelector("[data-ha-transition-attempt]");
    if (attempt) attempt.textContent = String(Number(failover.verification_attempt) || 0);
    const list = panel.querySelector("[data-ha-transition-steps]");
    if (list && Array.isArray(failover.steps)) {
      list.replaceChildren(...failover.steps.map((step) => {
        const item = document.createElement("li");
        item.className = `is-${["complete", "current", "pending"].includes(step.state) ? step.state : "pending"}`;
        item.textContent = step.label;
        return item;
      }));
    }
  }

  function updateMaintenanceProgress(maintenance) {
    const panel = document.querySelector("[data-ha-maintenance-panel]");
    if (!panel) return;
    const visible = maintenance && ["RUNNING", "FAILED_SAFE"].includes(maintenance.status);
    panel.hidden = !visible;
    if (!visible) return;
    const percent = Math.max(0, Math.min(100, Number(maintenance.progress_percent) || 0));
    const track = panel.querySelector('[role="progressbar"]');
    const bar = panel.querySelector("[data-ha-maintenance-bar]");
    if (track) track.setAttribute("aria-valuenow", String(percent));
    if (bar) bar.style.width = `${percent}%`;
    const titleElement = panel.querySelector("[data-ha-maintenance-title]");
    if (titleElement) titleElement.textContent = maintenance.message || "Cluster maintenance in progress";
    const status = panel.querySelector("[data-ha-maintenance-status]");
    if (status) status.textContent = title(maintenance.status);
    const elapsed = panel.querySelector("[data-ha-maintenance-elapsed]");
    if (elapsed) elapsed.textContent = `${Number(maintenance.elapsed_seconds) || 0}s`;
    const attempt = panel.querySelector("[data-ha-maintenance-attempt]");
    if (attempt) attempt.textContent = String(Number(maintenance.phase_attempt) || 0);
    const list = panel.querySelector("[data-ha-maintenance-progress]");
    if (list && Array.isArray(maintenance.steps)) {
      list.replaceChildren(...maintenance.steps.map((step) => {
        const item = document.createElement("li");
        item.className = `is-${["complete", "current", "pending"].includes(step.state) ? step.state : "pending"}`;
        item.textContent = step.label;
        return item;
      }));
    }
    const error = panel.querySelector("[data-ha-maintenance-error]");
    if (error) error.textContent = maintenance.error || "";
    const errorPanel = panel.querySelector("[data-ha-maintenance-error-panel]");
    if (errorPanel) errorPanel.hidden = !maintenance.error;
  }

  async function refresh() {
    if (root.dataset.loading === "1") return;
    root.dataset.loading = "1";
    try {
      const response = await fetch(root.dataset.liveUrl, {headers: {Accept: "application/json"}, cache: "no-store"});
      if (!response.ok) throw new Error("Live status unavailable");
      const data = await response.json();
      updateFields(document, "[data-ha-cluster-field]", data.cluster);
      document.querySelectorAll("[data-ha-single-node-service]").forEach((element) => {
        element.hidden = data.cluster.single_node_service !== true;
      });
      document.querySelectorAll("[data-ha-current-agent-version]").forEach((element) => { element.textContent = data.cluster.current_agent_version; });
      updateStatusChips(data.cluster.status);
      document.querySelectorAll("[data-ha-cluster-status]").forEach((element) => { element.textContent = title(data.cluster.keepalived_status); });
      document.querySelectorAll("[data-ha-generation]").forEach((element) => { element.textContent = data.cluster.keepalived_generation; });
      const vipSummary = data.nodes.filter((node) => node.vip_owned);
      document.querySelectorAll("[data-ha-vip-summary]").forEach((element) => { element.textContent = vipSummary.length === 1 ? vipSummary[0].name : vipSummary.length > 1 ? "Unsafe: multiple owners" : "No owner reported"; });
      updateNodes(data.nodes);
      updateDeploymentLiveStatus(data.nodes);
      if (data.lease) updateFields(document, "[data-ha-lease-field]", data.lease);
      updateFields(document, "[data-ha-failover-field]", data.failover);
      updateTransitionProgress(data.failover);
      updateMaintenanceProgress(data.maintenance);
      document.querySelectorAll("[data-ha-failover-diagnostic]").forEach((element) => {
        element.hidden = !data.failover.error;
      });
      document.querySelectorAll("[data-ha-failover-error]").forEach((element) => {
        element.textContent = data.failover.error || "";
      });
      document.querySelectorAll("[data-ha-failover-warning]").forEach((element) => {
        element.hidden = !data.failover.warnings?.length;
      });
      document.querySelectorAll("[data-ha-failover-warning-message]").forEach((element) => {
        const warnings = data.failover.warnings || [];
        element.textContent = warnings[warnings.length - 1] || "";
      });
      document.querySelectorAll("[data-ha-failover-rollback]").forEach((element) => {
        element.hidden = data.failover.status !== "FAILED_SAFE";
      });
      if (data.sync) {
        updateFields(document, "[data-ha-sync-field]", data.sync);
        document.querySelectorAll("[data-ha-sync-state]").forEach((element) => {
          element.dataset.haSyncState = String(data.sync.state || "waiting").toLowerCase();
        });
      }
      const issue = data.consistency?.issues?.[0];
      document.querySelectorAll("[data-ha-consistency-alert]").forEach((element) => { element.hidden = !issue; });
      document.querySelectorAll("[data-ha-consistency-title]").forEach((element) => { element.textContent = issue?.title || ""; });
      document.querySelectorAll("[data-ha-consistency-message]").forEach((element) => { element.textContent = issue?.message || ""; });
      updateReadiness(data.readiness);
      updateDeployment(data.deployment);
      updateEvents(data.events);
      document.querySelectorAll("[data-ha-live-indicator]").forEach((element) => { element.textContent = "Live"; setStateClass(element, true); });
      document.dispatchEvent(new CustomEvent("ha:live", {detail: data}));
    } catch (_) {
      document.querySelectorAll("[data-ha-live-indicator]").forEach((element) => { element.textContent = "Updates delayed"; setStateClass(element, false, true); });
      document.querySelectorAll("[data-ha-live-status]").forEach((element) => {
        element.classList.remove("is-connecting", "is-live", "is-delayed");
        element.classList.add("is-error");
      });
      document.querySelectorAll("[data-ha-live-label]").forEach((element) => { element.textContent = "Live updates unavailable"; });
    } finally { root.dataset.loading = "0"; }
  }

  const updateClocks = () => document.querySelectorAll("[data-ha-live-clock]").forEach((clock) => { clock.textContent = new Date().toLocaleString([], {dateStyle: "full", timeStyle: "medium"}); });
  updateClocks();
  window.setInterval(updateClocks, 1000);
  refresh();
  window.setInterval(refresh, 1000);
})();
