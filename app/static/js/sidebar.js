(function () {
  const storageKey = "homelab.sidebar.openMenus";
  const collapseStorageKey = "homelab.sidebar.collapsed";
  const dashboardPath = "/dashboard";
  const menus = Array.from(document.querySelectorAll("[data-sidebar-menu]"));
  const resetLinks = Array.from(document.querySelectorAll("[data-reset-sidebar]"));
  const collapseButton = document.querySelector("[data-sidebar-collapse]");
  document.documentElement.dataset.theme = "dark";
  localStorage.removeItem("homelab.theme");

  function setCollapsed(collapsed) {
    document.body.classList.toggle("sidebar-collapsed", collapsed);
    localStorage.setItem(collapseStorageKey, collapsed ? "1" : "0");
    if (collapseButton) {
      collapseButton.textContent = collapsed ? ">" : "<";
      collapseButton.title = collapsed ? "Expand sidebar" : "Collapse sidebar";
      collapseButton.setAttribute("aria-label", collapseButton.title);
    }
  }

  function saveState() {
    const openMenus = menus
      .filter((menu) => menu.open && menu.dataset.sidebarFlyout !== "1")
      .map((menu) => menu.dataset.sidebarMenu);
    localStorage.setItem(storageKey, JSON.stringify(openMenus));
  }

  function isCollapsed() {
    return document.body.classList.contains("sidebar-collapsed");
  }

  function closeFlyout(menu) {
    if (menu.dataset.sidebarFlyout !== "1") return;
    menu.open = false;
    delete menu.dataset.sidebarFlyout;
  }

  function closeFlyouts(except = null) {
    menus.forEach((menu) => {
      if (menu !== except) closeFlyout(menu);
    });
  }

  function openFlyout(menu) {
    if (!isCollapsed()) return;
    closeFlyouts(menu);
    menu.dataset.sidebarFlyout = "1";
    menu.open = true;
  }

  function clearState() {
    localStorage.removeItem(storageKey);
    menus.forEach((menu) => {
      menu.open = false;
    });
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

  setCollapsed(localStorage.getItem(collapseStorageKey) === "1");

  if (collapseButton) {
    collapseButton.addEventListener("click", () => {
      closeFlyouts();
      setCollapsed(!document.body.classList.contains("sidebar-collapsed"));
    });
  }

  menus.forEach((menu) => {
    const summary = menu.querySelector("summary");
    menu.addEventListener("mouseenter", () => openFlyout(menu));
    menu.addEventListener("mouseleave", () => closeFlyout(menu));
    menu.addEventListener("focusin", () => openFlyout(menu));
    menu.addEventListener("focusout", (event) => {
      if (!menu.contains(event.relatedTarget)) closeFlyout(menu);
    });
    if (summary) {
      summary.addEventListener("click", (event) => {
        if (!isCollapsed()) return;
        event.preventDefault();
        if (menu.open && menu.dataset.sidebarFlyout === "1") {
          closeFlyout(menu);
        } else {
          openFlyout(menu);
        }
      });
    }
  });

  document.querySelectorAll(".sidebar a.nav-link[href]").forEach((link) => {
    const href = link.getAttribute("href");
    if (href && (window.location.pathname === href || (!["/dashboard", "/admin"].includes(href) && window.location.pathname.startsWith(href + "/")))) {
      link.classList.add("active");
      link.closest("details")?.setAttribute("open", "");
      link.closest(".nav-group")?.setAttribute("open", "");
    }
  });

  document.addEventListener("click", (event) => {
    document.querySelectorAll(".account-menu[open]").forEach((menu) => {
      if (!menu.contains(event.target)) {
        menu.open = false;
      }
    });
  });
})();
