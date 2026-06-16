(() => {
  const root = document.querySelector("[data-remote-tabs]");
  if (!root) return;

  const tabbar = root.querySelector("[data-remote-tabbar]");
  const panels = root.querySelector("[data-remote-tab-panels]");
  const empty = root.querySelector("[data-remote-empty]");
  const storageKey = "homelab.remote.tabs.v1";
  if (!tabbar || !panels || !empty) return;

  let tabs = [];
  let activeId = "";

  const safeParse = (value) => {
    try {
      return JSON.parse(value || "{}");
    } catch {
      return {};
    }
  };

  const save = () => {
    window.sessionStorage.setItem(storageKey, JSON.stringify({ tabs, activeId }));
  };

  const hostFromCard = (card) => ({
    id: `remote-${card.dataset.remoteId}-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    remoteId: card.dataset.remoteId,
    label: card.dataset.remoteLabel || "Remote host",
    protocol: (card.dataset.remoteProtocol || "ssh").toLowerCase(),
    url: card.dataset.remotePanelUrl,
  });

  const activate = (id) => {
    activeId = id;
    render();
    const iframe = panels.querySelector(`[data-remote-panel="${CSS.escape(id)}"] iframe`);
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: "homelab:remote-tab-active" }, window.location.origin);
    }
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
    render();
    save();
  };

  const refreshTab = (id) => {
    const iframe = panels.querySelector(`[data-remote-panel="${CSS.escape(id)}"] iframe`);
    if (iframe) iframe.src = iframe.src;
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

  const render = () => {
    tabbar.replaceChildren();
    empty.hidden = tabs.length > 0;

    tabs.forEach((tab) => {
      const button = document.createElement("div");
      button.className = `remote-session-tab${tab.id === activeId ? " active" : ""}`;
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
      refresh.title = "Refresh connection";
      refresh.textContent = "r";
      refresh.addEventListener("click", (event) => {
        event.stopPropagation();
        refreshTab(tab.id);
      });

      const close = document.createElement("button");
      close.type = "button";
      close.className = "remote-tab-tool";
      close.title = "Close session";
      close.textContent = "x";
      close.addEventListener("click", (event) => {
        event.stopPropagation();
        closeTab(tab.id);
      });

      tools.append(refresh, close);
      button.appendChild(tools);
      tabbar.appendChild(button);
    });

    tabs.forEach((tab) => {
      const panel = ensurePanel(tab);
      panel.hidden = tab.id !== activeId;
    });

    const activeFrame = panels.querySelector(`[data-remote-panel="${CSS.escape(activeId)}"] iframe`);
    if (activeFrame && activeFrame.contentWindow) {
      window.setTimeout(() => {
        activeFrame.contentWindow.postMessage({ type: "homelab:remote-tab-active" }, window.location.origin);
      }, 50);
    }

    panels.querySelectorAll("[data-remote-panel]").forEach((panel) => {
      if (!tabs.some((tab) => tab.id === panel.dataset.remotePanel)) {
        panel.remove();
      }
    });

    root.querySelectorAll(".remote-host-card").forEach((card) => {
      const activeTab = tabs.find((tab) => tab.id === activeId);
      card.classList.toggle("active", activeTab && activeTab.remoteId === card.dataset.remoteId);
    });
  };

  const openTab = (session) => {
    if (!session.url) return;
    tabs.push(session);
    activeId = session.id;
    render();
    save();
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

  const restored = safeParse(window.sessionStorage.getItem(storageKey));
  tabs = Array.isArray(restored.tabs) ? restored.tabs : [];
  activeId = restored.activeId || tabs[0]?.id || "";
  render();
})();
