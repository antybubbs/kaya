(() => {
  const root = document.querySelector("[data-remote-tabs]");
  if (!root) return;

  const tabbar = root.querySelector("[data-remote-tabbar]");
  const panels = root.querySelector("[data-remote-tab-panels]");
  const empty = root.querySelector("[data-remote-empty]");
  const searchInput = root.querySelector("[data-remote-search]");
  const groupToggle = root.querySelector("[data-remote-group-toggle]");
  const refreshTabsButton = root.querySelector("[data-remote-refresh-tabs]");
  const hostList = root.querySelector(".remote-host-list");
  const hostRail = root.querySelector(".remote-host-rail");
  const hostResizer = root.querySelector("[data-remote-host-resizer]");
  const noResults = root.querySelector("[data-remote-no-results]");
  const sessionVersion = root.dataset.remoteSessionVersion || "1";
  const storageKey = `homelab.remote.tabs.${sessionVersion}`;
  const railWidthStorageKey = "homelab.remote.hostRailWidth";
  const groupViewStorageKey = "homelab.remote.groupView";
  if (!tabbar || !panels || !empty) return;

  let tabs = [];
  let activeId = "";
  let splitEnabled = false;
  let splitIds = [];
  let groupViewEnabled = localStorage.getItem(groupViewStorageKey) === "1";

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
    const nextWidth = clamp(width, 96, 520);
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
      iframe.contentWindow.postMessage({ type: "homelab:remote-tab-active" }, window.location.origin);
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

  const closeTab = (id) => {
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
      iframe.contentWindow.postMessage({ type: "homelab:remote-display-refresh" }, window.location.origin);
      return;
    }
    iframe.src = iframe.src;
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

      const refresh = document.createElement("button");
      refresh.type = "button";
      refresh.className = "remote-tab-tool";
      refresh.title = tab.protocol === "rdp" ? "Refresh display size" : "Refresh connection";
      refresh.textContent = "R";
      refresh.addEventListener("click", (event) => {
        event.stopPropagation();
        refreshTab(tab.id);
      });

      const close = document.createElement("button");
      close.type = "button";
      close.className = "remote-tab-tool";
      close.title = "Close session";
      close.textContent = "X";
      close.addEventListener("click", (event) => {
        event.stopPropagation();
        closeTab(tab.id);
      });

      tools.append(refresh, close);
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

    shownIds.forEach((id) => notifyPanel(id));

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
    let visible = 0;
    root.querySelectorAll(".remote-host-card").forEach((card) => {
      const text = (card.dataset.remoteSearchText || "").toLowerCase();
      const hidden = query.length > 0 && !text.includes(query);
      card.hidden = hidden;
      if (!hidden) visible += 1;
    });
    root.querySelectorAll(".remote-host-group-heading").forEach((heading) => {
      const category = heading.dataset.remoteCategory;
      heading.hidden = !Array.from(root.querySelectorAll(".remote-host-card")).some(
        (card) => card.dataset.remoteCategory === category && !card.hidden,
      );
    });
    if (noResults) noResults.hidden = visible > 0;
  };

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
        const heading = document.createElement("div");
        heading.className = "remote-host-group-heading";
        heading.dataset.remoteCategory = category;
        const name = document.createElement("strong");
        const count = document.createElement("span");
        name.textContent = category;
        count.textContent = String(groups.get(category).length);
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
      if (menu !== except) menu.open = false;
    });
  };

  root.addEventListener("toggle", (event) => {
    const menu = event.target.closest(".remote-connect-menu");
    if (menu && menu.open) closeMenus(menu);
  }, true);

  root.addEventListener("click", (event) => {
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

  if (refreshTabsButton) {
    refreshTabsButton.addEventListener("click", () => {
      visibleIds().forEach((id) => refreshTab(id));
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
