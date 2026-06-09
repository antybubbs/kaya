(function () {
  const storageKey = "homelab.sidebar.openMenus";
  const dashboardPath = "/dashboard";
  const menus = Array.from(document.querySelectorAll("[data-sidebar-menu]"));
  const resetLinks = Array.from(document.querySelectorAll("[data-reset-sidebar]"));
  const themeKey = "homelab.theme";
  const themeToggles = Array.from(document.querySelectorAll("[data-theme-toggle]"));
  const collapseKey = "homelab.sidebar.collapsed";
  const collapseToggle = document.querySelector("[data-sidebar-collapse]");

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    themeToggles.forEach((themeToggle) => {
      themeToggle.setAttribute("aria-label", "Toggle light and dark mode");
    });
  }

  function saveState() {
    const openMenus = menus
      .filter((menu) => menu.open)
      .map((menu) => menu.dataset.sidebarMenu);
    localStorage.setItem(storageKey, JSON.stringify(openMenus));
  }

  function clearState() {
    localStorage.removeItem(storageKey);
    menus.forEach((menu) => {
      menu.open = false;
    });
  }

  function applyCollapsed(collapsed) {
    document.body.classList.toggle("sidebar-collapsed", collapsed);
    if (collapseToggle) {
      collapseToggle.textContent = "\u2630";
      collapseToggle.setAttribute("aria-label", collapsed ? "Expand sidebar" : "Collapse sidebar");
      collapseToggle.setAttribute("title", collapsed ? "Expand sidebar" : "Collapse sidebar");
    }
  }

  if (window.location.pathname === dashboardPath) {
    clearState();
  } else {
    try {
      const openMenus = new Set(JSON.parse(localStorage.getItem(storageKey) || "[]"));
      menus.forEach((menu) => {
        menu.open = openMenus.has(menu.dataset.sidebarMenu);
      });
    } catch {
      clearState();
    }
  }

  menus.forEach((menu) => {
    menu.addEventListener("toggle", saveState);
  });

  resetLinks.forEach((link) => {
    link.addEventListener("click", clearState);
  });

  const savedTheme = localStorage.getItem(themeKey) || "light";
  applyTheme(savedTheme);
  themeToggles.forEach((themeToggle) => {
    themeToggle.addEventListener("click", () => {
      const nextTheme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      localStorage.setItem(themeKey, nextTheme);
      applyTheme(nextTheme);
    });
  });

  const savedCollapsed = localStorage.getItem(collapseKey) === "true";
  applyCollapsed(savedCollapsed);
  if (collapseToggle) {
    collapseToggle.addEventListener("click", () => {
      const collapsed = !document.body.classList.contains("sidebar-collapsed");
      localStorage.setItem(collapseKey, String(collapsed));
      applyCollapsed(collapsed);
    });
  }
})();
