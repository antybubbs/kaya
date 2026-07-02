(() => {
  const root = document.querySelector("[data-remote-tabs]");
  if (!root) return;

  const tabbar = root.querySelector("[data-remote-tabbar]");
  const panels = root.querySelector("[data-remote-tab-panels]");
  const empty = root.querySelector("[data-remote-empty]");
  const searchInput = root.querySelector("[data-remote-search]");
  const groupToggle = root.querySelector("[data-remote-group-toggle]");
  const hostList = root.querySelector(".remote-host-list");
  const hostRail = root.querySelector(".remote-host-rail");
  const hostResizer = root.querySelector("[data-remote-host-resizer]");
  const noResults = root.querySelector("[data-remote-no-results]");
  const sessionVersion = root.dataset.remoteSessionVersion || "1";
  const storageKey = `kaya.remote.tabs.${sessionVersion}`;
  const railWidthStorageKey = "kaya.remote.hostRailWidth";
  const groupViewStorageKey = "kaya.remote.groupView";
  const collapsedGroupsStorageKey = "kaya.remote.collapsedGroups";
  const minimumHostRailWidth = 200;
  if (!tabbar || !panels || !empty) return;

  let tabs = [];
  let activeId = "";
  let splitEnabled = false;
  let splitIds = [];
  let groupViewEnabled = localStorage.getItem(groupViewStorageKey) !== "0";
  let collapsedGroups = new Set();
  const pendingPopouts = new Map();
  const pendingRecordingStops = new Map();

  const safeParse = (value) => {
    try {
      return JSON.parse(value || "{}");
    } catch {
      return {};
    }
  };

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

  const setHostRailWidth = (width) => {
    if (!hostRail) return;
    const nextWidth = clamp(width, minimumHostRailWidth, 520);
    root.style.setProperty("--remote-host-rail-width", `${nextWidth}px`);
    root.classList.toggle("remote-rail-compact", nextWidth < 230);
    root.classList.toggle("remote-rail-mini", nextWidth < 150);
    localStorage.setItem(railWidthStorageKey, String(nextWidth));
  };

  const save = () => {
    window.sessionStorage.setItem(storageKey, JSON.stringify({ tabs, activeId, splitEnabled, splitIds }));
  };

  const hostFromCard = (card) => ({
    id: `remote-${card.dataset.remoteId}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    remoteId: card.dataset.remoteId,
    label: card.dataset.remoteLabel || "Remote host",
    protocol: (card.dataset.remoteProtocol || "ssh").toLowerCase(),
    url: card.dataset.remotePanelUrl,
  });

  const notifyPanel = (id, delay = 50) => {
    const iframe = panels.querySelector(`[data-remote-panel="${CSS.escape(id)}"] iframe`);
    if (!iframe || !iframe.contentWindow) return;
    window.setTimeout(() => {
      iframe.contentWindow.postMessage({ type: "kaya:remote-tab-active" }, window.location.origin);
    }, delay);
  };

  const visibleIds = () => {
    if (!splitEnabled) return activeId ? [activeId] : [];

    const validSplitIds = splitIds.filter((id) => tabs.some((tab) => tab.id === id));
    const ids = [];
    if (activeId && validSplitIds.includes(activeId)) ids.push(activeId);
    validSplitIds.forEach((id) => {
      if (!ids.includes(id)) ids.push(id);
    });
    if (activeId && !ids.includes(activeId)) ids.unshift(activeId);
    tabs.forEach((tab) => {
      if (ids.length < 2 && !ids.includes(tab.id)) ids.push(tab.id);
    });

    splitIds = ids.slice(0, 2);
    return splitIds;
  };

  const activate = (id) => {
    if (splitEnabled && tabs.length > 1 && !splitIds.includes(id)) {
      const anchorId = splitIds.find((splitId) => splitId !== activeId) || activeId || tabs[0]?.id || id;
      splitIds = anchorId === id ? [id] : [anchorId, id];
    }
    activeId = id;
    render();
    notifyPanel(id, 0);
    save();
  };

  const requestRecordingStop = (id) => {
    const tab = tabs.find((candidate) => candidate.id === id);
    const iframe = iframeForTab(id);
    if (!tab?.recording?.active || !iframe?.contentWindow) return Promise.resolve();
    tab.recording = { ...tab.recording, available: false, status: "Saving" };
    render();
    save();
    const requestId = `recording-stop-${id}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    return new Promise((resolve) => {
      const timeout = window.setTimeout(() => {
        pendingRecordingStops.delete(requestId);
        resolve();
      }, 120000);
      pendingRecordingStops.set(requestId, { resolve, timeout });
      iframe.contentWindow.postMessage({ type: "kaya:remote-recording-stop", requestId }, window.location.origin);
    });
  };

  const closeTab = async (id) => {
    await requestRecordingStop(id);
    const index = tabs.findIndex((tab) => tab.id === id);
    tabs = tabs.filter((tab) => tab.id !== id);
    const panel = panels.querySelector(`[data-remote-panel="${CSS.escape(id)}"]`);
    if (panel) panel.remove();
    if (activeId === id) {
      activeId = tabs[Math.max(0, index - 1)]?.id || tabs[0]?.id || "";
    }
    splitIds = splitIds.filter((splitId) => splitId !== id);
    if (tabs.length < 2) splitEnabled = false;
    render();
    save();
  };

  const refreshTab = (id) => {
    const iframe = panels.querySelector(`[data-remote-panel="${CSS.escape(id)}"] iframe`);
    const tab = tabs.find((candidate) => candidate.id === id);
    if (!iframe || !tab) return;
    if (tab.protocol === "rdp" && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: "kaya:remote-display-refresh" }, window.location.origin);
      return;
    }
    iframe.src = iframe.src;
  };

  const iframeForTab = (id) => panels.querySelector(`[data-remote-panel="${CSS.escape(id)}"] iframe`);

  const queryRecordingState = (id) => {
    const iframe = iframeForTab(id);
    if (!iframe || !iframe.contentWindow) return;
    iframe.contentWindow.postMessage({ type: "kaya:remote-recording-query" }, window.location.origin);
  };

  const toggleRecording = (id) => {
    const iframe = iframeForTab(id);
    if (!iframe || !iframe.contentWindow) return;
    iframe.contentWindow.postMessage({ type: "kaya:remote-recording-toggle" }, window.location.origin);
  };

  const tabIdForSource = (source) => {
    const panel = Array.from(panels.querySelectorAll("[data-remote-panel]")).find((candidate) => {
      const iframe = candidate.querySelector("iframe");
      return iframe && iframe.contentWindow === source;
    });
    return panel?.dataset.remotePanel || "";
  };

  const updateRecordingState = (id, state) => {
    const tab = tabs.find((candidate) => candidate.id === id);
    if (!tab) return;
    const nextRecording = {
      enabled: Boolean(state.enabled),
      available: Boolean(state.available),
      active: Boolean(state.active),
      label: state.label || (state.active ? "Stop" : "Record"),
      status: state.status || "Ready",
    };
    const current = tab.recording || {};
    if (
      current.enabled === nextRecording.enabled
      && current.available === nextRecording.available
      && current.active === nextRecording.active
      && current.label === nextRecording.label
      && current.status === nextRecording.status
    ) {
      return;
    }
    tab.recording = nextRecording;
    render();
    save();
  };

  const sessionWindowFeatures = () => {
    const width = Math.min(1600, Math.max(960, Math.floor(window.screen.availWidth * 0.82)));
    const height = Math.min(1000, Math.max(640, Math.floor(window.screen.availHeight * 0.82)));
    const left = Math.max(0, Math.floor((window.screen.availWidth - width) / 2));
    const top = Math.max(0, Math.floor((window.screen.availHeight - height) / 2));
    return `popup=yes,width=${width},height=${height},left=${left},top=${top},resizable=yes,scrollbars=no`;
  };

  const popOutSession = (session) => {
    if (!session?.url) return;
    const name = `kaya_remote_${session.remoteId}_${session.protocol}`;
    const url = new URL(session.url, window.location.origin);
    url.searchParams.set("popout", "1");
    const opened = window.open(url.toString(), name, sessionWindowFeatures());
    if (opened) opened.focus();
  };

  const openRdpPopoutForHandoff = (tab, token, requestId) => {
    const name = `kaya_remote_${tab.remoteId}_${tab.protocol}`;
    const url = new URL(tab.url, window.location.origin);
    url.searchParams.set("popout", "1");
    const hash = new URLSearchParams();
    hash.set("requestId", requestId);
    url.hash = hash.toString();
    const opened = window.open(url.toString(), name, sessionWindowFeatures());
    const pending = pendingPopouts.get(requestId);
    if (pending) {
      pending.token = token;
      pending.window = opened;
    }
    if (opened) opened.focus();
  };

  const requestRdpPopoutHandoff = (tab) => {
    const iframe = panels.querySelector(`[data-remote-panel="${CSS.escape(tab.id)}"] iframe`);
    if (!iframe || !iframe.contentWindow) {
      popOutSession(tab);
      return;
    }
    const requestId = `popout-${tab.id}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const timeout = window.setTimeout(() => {
      pendingPopouts.delete(requestId);
      popOutSession(tab);
    }, 900);
    pendingPopouts.set(requestId, { tabId: tab.id, timeout });
    iframe.contentWindow.postMessage({ type: "kaya:remote-popout-request", requestId }, window.location.origin);
  };

  const ensurePanel = (tab) => {
    let panel = panels.querySelector(`[data-remote-panel="${CSS.escape(tab.id)}"]`);
    if (panel) return panel;
    panel = document.createElement("section");
    panel.className = "remote-tab-panel";
    panel.dataset.remotePanel = tab.id;
    const iframe = document.createElement("iframe");
    iframe.title = `${tab.label} ${tab.protocol.toUpperCase()} session`;
    iframe.src = tab.url;
    iframe.loading = "eager";
    iframe.referrerPolicy = "same-origin";
    iframe.addEventListener("load", () => queryRecordingState(tab.id));
    panel.appendChild(iframe);
    panels.appendChild(panel);
    return panel;
  };

  const iconFor = (protocol) => (protocol === "rdp" ? "RDP" : ">_");

  const setSplitEnabled = (enabled) => {
    splitEnabled = enabled && tabs.length > 1;
    if (splitEnabled) {
      const current = activeId || tabs[0]?.id || "";
      const other = tabs.find((tab) => tab.id !== current)?.id || "";
      splitIds = [current, other].filter(Boolean).slice(0, 2);
    } else {
      splitIds = [];
    }
    render();
    save();
  };

  const ensureLayoutTools = () => {
    const tools = document.createElement("div");
    tools.className = "remote-layout-tools";
    tools.dataset.remoteLayoutTools = "";

    const split = document.createElement("button");
    split.type = "button";
    split.className = `remote-layout-button${splitEnabled ? " active" : ""}`;
    split.title = tabs.length > 1 ? "Show two sessions side by side" : "Open two sessions to use split view";
    split.disabled = tabs.length < 2;
    split.textContent = splitEnabled ? "Single" : "Split";
    split.addEventListener("click", () => setSplitEnabled(!splitEnabled));

    tools.appendChild(split);
    tabbar.appendChild(tools);
  };

  const render = () => {
    tabbar.replaceChildren();
    empty.hidden = tabs.length > 0;
    if (tabs.length < 2) splitEnabled = false;
    const shownIds = visibleIds();

    tabs.forEach((tab) => {
      const visible = shownIds.includes(tab.id);
      const button = document.createElement("div");
      button.className = `remote-session-tab${tab.id === activeId ? " active" : ""}${visible && splitEnabled ? " split-visible" : ""}`;
      button.setAttribute("role", "button");
      button.setAttribute("tabindex", "0");
      button.dataset.remoteTab = tab.id;
      button.innerHTML = `<span class="remote-tab-icon">${iconFor(tab.protocol)}</span><span class="remote-tab-title"></span><span class="remote-tab-protocol">${tab.protocol.toUpperCase()}</span>`;
      button.querySelector(".remote-tab-title").textContent = tab.label;
      button.addEventListener("click", () => activate(tab.id));
      button.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          activate(tab.id);
        }
      });

      const tools = document.createElement("span");
      tools.className = "remote-tab-tools";

      const record = document.createElement("button");
      const recording = tab.recording || {};
      record.type = "button";
      record.className = `remote-tab-tool remote-tab-record${recording.active ? " active" : ""}`;
      record.title = recording.status ? `Session recording: ${recording.status}` : "Session recording";
      record.textContent = recording.active ? "S" : "Rec";
      record.disabled = !recording.available;
      record.addEventListener("click", (event) => {
        event.stopPropagation();
        toggleRecording(tab.id);
      });

      const refresh = document.createElement("button");
      refresh.type = "button";
      refresh.className = "remote-tab-tool";
      refresh.title = tab.protocol === "rdp" ? "Refresh display size" : "Refresh connection";
      refresh.textContent = "R";
      refresh.addEventListener("click", (event) => {
        event.stopPropagation();
        refreshTab(tab.id);
      });

      const popout = document.createElement("button");
      popout.type = "button";
      popout.className = "remote-tab-tool";
      popout.title = "Pop out session";
      popout.textContent = "P";
      popout.addEventListener("click", (event) => {
        event.stopPropagation();
        if (tab.protocol === "rdp") {
          requestRdpPopoutHandoff(tab);
          return;
        }
        popOutSession(tab);
      });

      const close = document.createElement("button");
      close.type = "button";
      close.className = "remote-tab-tool";
      close.title = "Close session";
      close.textContent = "X";
      close.addEventListener("click", async (event) => {
        event.stopPropagation();
        close.disabled = true;
        await closeTab(tab.id);
      });

      tools.append(record, refresh, popout, close);
      button.appendChild(tools);
      tabbar.appendChild(button);
    });

    ensureLayoutTools();
    panels.classList.toggle("is-split", splitEnabled && shownIds.length > 1);

    tabs.forEach((tab) => {
      const panel = ensurePanel(tab);
      const visible = shownIds.includes(tab.id);
      panel.hidden = !visible;
      panel.classList.toggle("split-primary", splitEnabled && tab.id === shownIds[0]);
      panel.classList.toggle("split-secondary", splitEnabled && tab.id === shownIds[1]);
    });

    shownIds.forEach((id) => {
      notifyPanel(id);
      queryRecordingState(id);
    });

    panels.querySelectorAll("[data-remote-panel]").forEach((panel) => {
      if (!tabs.some((tab) => tab.id === panel.dataset.remotePanel)) {
        panel.remove();
      }
    });

    root.querySelectorAll(".remote-host-card").forEach((card) => {
      const activeTab = tabs.find((tab) => tab.id === activeId);
      const splitTab = tabs.find((tab) => splitEnabled && shownIds.includes(tab.id) && tab.remoteId === card.dataset.remoteId);
      card.classList.toggle("active", activeTab && activeTab.remoteId === card.dataset.remoteId);
      card.classList.toggle("split-active", Boolean(splitTab));
    });
  };

  const openTab = (session) => {
    if (!session.url) return;
    const existing = tabs.find((tab) => tab.remoteId === session.remoteId && tab.protocol === session.protocol);
    if (existing) {
      activate(existing.id);
      return;
    }
    tabs.push(session);
    activeId = session.id;
    if (splitEnabled && tabs.length > 1) {
      splitIds = [splitIds[0] || tabs[0].id, session.id].filter(Boolean).slice(0, 2);
    }
    render();
    save();
  };

  const filterHosts = () => {
    const query = (searchInput?.value || "").trim().toLowerCase();
    let matches = 0;
    root.querySelectorAll(".remote-host-card").forEach((card) => {
      const text = (card.dataset.remoteSearchText || "").toLowerCase();
      const matchesQuery = query.length === 0 || text.includes(query);
      const collapsed = groupViewEnabled && query.length === 0 && collapsedGroups.has(card.dataset.remoteCategory);
      card.hidden = !matchesQuery || collapsed;
      if (matchesQuery) matches += 1;
    });
    root.querySelectorAll(".remote-host-group-heading").forEach((heading) => {
      const category = heading.dataset.remoteCategory;
      heading.hidden = !Array.from(root.querySelectorAll(".remote-host-card")).some(
        (card) => card.dataset.remoteCategory === category
          && (query.length === 0 || (card.dataset.remoteSearchText || "").toLowerCase().includes(query)),
      );
    });
    if (noResults) noResults.hidden = matches > 0;
  };
  const storedCollapsedGroups = safeParse(localStorage.getItem(collapsedGroupsStorageKey));
  collapsedGroups = new Set(Array.isArray(storedCollapsedGroups) ? storedCollapsedGroups : []);

  const applyHostGrouping = () => {
    if (!hostList) return;
    hostList.querySelectorAll(".remote-host-group-heading").forEach((heading) => heading.remove());
    const cards = Array.from(hostList.querySelectorAll(".remote-host-card"));
    if (groupViewEnabled) {
      const groups = new Map();
      cards.forEach((card) => {
        const category = card.dataset.remoteCategory || "Uncategorised";
        if (!groups.has(category)) groups.set(category, []);
        groups.get(category).push(card);
      });
      Array.from(groups.keys()).sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" })).forEach((category) => {
        const heading = document.createElement("button");
        heading.type = "button";
        heading.className = "remote-host-group-heading";
        heading.dataset.remoteCategory = category;
        const name = document.createElement("strong");
        const count = document.createElement("span");
        const collapsed = collapsedGroups.has(category);
        name.textContent = category;
        count.textContent = String(groups.get(category).length);
        heading.classList.toggle("collapsed", collapsed);
        heading.setAttribute("aria-expanded", collapsed ? "false" : "true");
        heading.addEventListener("click", () => {
          if (collapsedGroups.has(category)) collapsedGroups.delete(category);
          else collapsedGroups.add(category);
          localStorage.setItem(collapsedGroupsStorageKey, JSON.stringify(Array.from(collapsedGroups)));
          applyHostGrouping();
        });
        heading.append(name, count);
        hostList.append(heading, ...groups.get(category));
      });
    } else {
      cards.sort((a, b) => Number(a.dataset.remoteOrder) - Number(b.dataset.remoteOrder));
      hostList.append(...cards);
    }
    if (groupToggle) {
      groupToggle.classList.toggle("active", groupViewEnabled);
      groupToggle.textContent = groupViewEnabled ? "List" : "Grp";
      groupToggle.title = groupViewEnabled ? "Show a flat host list" : "Group hosts by IP/WAN category";
    }
    filterHosts();
  };

  const closeMenus = (except = null) => {
    root.querySelectorAll(".remote-connect-menu[open]").forEach((menu) => {
      if (menu !== except) {
        menu.open = false;
        const panel = menu.querySelector("div");
        if (panel) {
          panel.style.left = "";
          panel.style.top = "";
        }
      }
    });
  };

  const positionConnectMenu = (menu) => {
    const summary = menu?.querySelector("summary");
    const panel = menu?.querySelector("div");
    if (!summary || !panel || !menu.open) return;

    panel.style.left = "0px";
    panel.style.top = "0px";
    const summaryRect = summary.getBoundingClientRect();
    const panelRect = panel.getBoundingClientRect();
    const margin = 8;
    const left = clamp(summaryRect.right - panelRect.width, margin, window.innerWidth - panelRect.width - margin);
    const top = clamp(summaryRect.bottom + 4, margin, window.innerHeight - panelRect.height - margin);
    panel.style.left = `${left}px`;
    panel.style.top = `${top}px`;
  };

  const positionOpenConnectMenu = () => {
    positionConnectMenu(root.querySelector(".remote-connect-menu[open]"));
  };

  root.addEventListener("toggle", (event) => {
    const menu = event.target.closest(".remote-connect-menu");
    if (menu && menu.open) {
      closeMenus(menu);
      positionConnectMenu(menu);
    }
  }, true);

  root.addEventListener("click", (event) => {
    const popoutLink = event.target.closest("[data-remote-popout]");
    if (popoutLink) {
      const card = popoutLink.closest(".remote-host-card");
      if (!card) return;
      event.preventDefault();
      closeMenus();
      popOutSession(hostFromCard(card));
      return;
    }

    const link = event.target.closest("[data-remote-open]");
    if (!link) {
      if (!event.target.closest(".remote-connect-menu")) closeMenus();
      return;
    }
    const card = link.closest(".remote-host-card");
    if (!card) return;
    event.preventDefault();
    closeMenus();
    openTab(hostFromCard(card));
  });

  document.addEventListener("click", (event) => {
    if (!root.contains(event.target)) closeMenus();
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeMenus();
  });

  window.addEventListener("message", (event) => {
    if (event.origin !== window.location.origin) return;
    const data = event.data || {};
    if (data.type === "kaya:remote-recording-state") {
      const tabId = tabIdForSource(event.source);
      if (tabId) updateRecordingState(tabId, data);
      return;
    }
    if (data.type === "kaya:remote-recording-stopped") {
      const pending = pendingRecordingStops.get(data.requestId);
      if (!pending) return;
      window.clearTimeout(pending.timeout);
      pendingRecordingStops.delete(data.requestId);
      pending.resolve();
      return;
    }
    if (data.type === "kaya:remote-popout-state") {
      const pending = pendingPopouts.get(data.requestId);
      if (!pending) return;
      window.clearTimeout(pending.timeout);
      const tab = tabs.find((candidate) => candidate.id === pending.tabId);
      if (!tab) {
        pendingPopouts.delete(data.requestId);
        return;
      }
      if (data.ok && data.token) {
        pending.timeout = window.setTimeout(() => pendingPopouts.delete(data.requestId), 30000);
        openRdpPopoutForHandoff(tab, data.token, data.requestId);
      } else {
        pendingPopouts.delete(data.requestId);
        popOutSession(tab);
      }
    }
    if (data.type === "kaya:remote-popout-ready") {
      const pending = pendingPopouts.get(data.requestId);
      if (!pending?.token || !event.source) return;
      event.source.postMessage({
        type: "kaya:remote-popout-connect",
        requestId: data.requestId,
        token: pending.token,
      }, event.origin);
    }
    if (data.type === "kaya:remote-popout-connected") {
      const pending = pendingPopouts.get(data.requestId);
      const tabId = pending?.tabId || "";
      const iframe = tabId ? panels.querySelector(`[data-remote-panel="${CSS.escape(tabId)}"] iframe`) : null;
      if (iframe && iframe.contentWindow) {
        iframe.contentWindow.postMessage({ type: "kaya:remote-popout-detached" }, window.location.origin);
      }
      if (pending) {
        window.clearTimeout(pending.timeout);
        pendingPopouts.delete(data.requestId);
      }
    }
  });

  window.addEventListener("resize", positionOpenConnectMenu);
  hostList?.addEventListener("scroll", positionOpenConnectMenu, { passive: true });

  if (searchInput) {
    searchInput.addEventListener("input", filterHosts);
    searchInput.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        searchInput.value = "";
        filterHosts();
        searchInput.blur();
      }
    });
  }

  if (groupToggle) {
    groupToggle.addEventListener("click", () => {
      groupViewEnabled = !groupViewEnabled;
      localStorage.setItem(groupViewStorageKey, groupViewEnabled ? "1" : "0");
      applyHostGrouping();
    });
  }

  if (hostRail && hostResizer) {
    const storedWidth = Number.parseInt(localStorage.getItem(railWidthStorageKey) || "", 10);
    if (Number.isFinite(storedWidth)) setHostRailWidth(storedWidth);

    hostResizer.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      const startX = event.clientX;
      const startWidth = hostRail.getBoundingClientRect().width;
      hostResizer.setPointerCapture(event.pointerId);
      document.body.classList.add("remote-resizing");

      const move = (moveEvent) => {
        setHostRailWidth(startWidth + moveEvent.clientX - startX);
        positionOpenConnectMenu();
      };

      const stop = () => {
        document.body.classList.remove("remote-resizing");
        hostResizer.removeEventListener("pointermove", move);
        hostResizer.removeEventListener("pointerup", stop);
        hostResizer.removeEventListener("pointercancel", stop);
      };

      hostResizer.addEventListener("pointermove", move);
      hostResizer.addEventListener("pointerup", stop);
      hostResizer.addEventListener("pointercancel", stop);
    });
  }

  const restored = safeParse(window.sessionStorage.getItem(storageKey));
  tabs = Array.isArray(restored.tabs) ? restored.tabs : [];
  activeId = restored.activeId || tabs[0]?.id || "";
  splitEnabled = Boolean(restored.splitEnabled);
  splitIds = Array.isArray(restored.splitIds) ? restored.splitIds : [];
  applyHostGrouping();
  render();
})();
