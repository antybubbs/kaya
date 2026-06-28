(() => {
  const root = document.querySelector("[data-settings-tabs]");
  if (!root) return;

  const tabs = Array.from(root.querySelectorAll("[data-settings-tab]"));
  const panels = Array.from(root.querySelectorAll("[data-settings-panel]"));
  const storageKey = "kaya.siteAdministration.activeTab";

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
      window.localStorage.setItem(storageKey, activeName);
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => activate(tab.dataset.settingsTab));
  });

  activate(window.localStorage.getItem(storageKey) || tabs[0]?.dataset.settingsTab || "");
})();
