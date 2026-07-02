(() => {
  const root = document.querySelector("[data-settings-tabs]");
  if (!root) return;

  const tabs = Array.from(root.querySelectorAll("[data-settings-tab]"));
  const panels = Array.from(root.querySelectorAll("[data-settings-panel]"));
  const storageKey = root.dataset.settingsStorageKey || "kaya.siteAdministration.activeTab";

  const readStoredTab = () => {
    try {
      return window.localStorage.getItem(storageKey);
    } catch {
      return "";
    }
  };

  const writeStoredTab = (name) => {
    try {
      window.localStorage.setItem(storageKey, name);
    } catch {
      // Tab switching should still work when browser storage is unavailable.
    }
  };

  const activate = (name) => {
    const fallback = tabs[0]?.dataset.settingsTab || "";
    const activeName = panels.some((panel) => panel.dataset.settingsPanel === name) ? name : fallback;

    tabs.forEach((tab) => {
      const active = tab.dataset.settingsTab === activeName;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });

    panels.forEach((panel) => {
      const active = panel.dataset.settingsPanel === activeName;
      panel.hidden = !active;
      panel.classList.toggle("active", active);
    });

    if (activeName) {
      writeStoredTab(activeName);
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => activate(tab.dataset.settingsTab));
  });

  activate(readStoredTab() || tabs[0]?.dataset.settingsTab || "");
})();
