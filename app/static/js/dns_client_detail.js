(function () {
  const panelSelector = "#dns-traffic-history";
  const tableSelector = '[data-table-key="dns-client-traffic-history"]';
  let requestController = null;

  async function refreshTrafficPanel(url, updateHistory) {
    const panel = document.querySelector(panelSelector);
    const currentTable = panel?.querySelector(tableSelector);
    if (!panel || !currentTable) return;

    requestController?.abort();
    const controller = new AbortController();
    requestController = controller;
    panel.setAttribute("aria-busy", "true");
    const scrollTop = window.scrollY;

    try {
      const response = await fetch(url, {
        headers: { "X-Requested-With": "XMLHttpRequest" },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Traffic page request failed: ${response.status}`);
      const documentCopy = new DOMParser().parseFromString(await response.text(), "text/html");
      const nextPanel = documentCopy.querySelector(panelSelector);
      const nextTable = nextPanel?.querySelector(tableSelector);
      if (!nextPanel || !nextTable) throw new Error("Traffic table was missing from the response.");

      [".dns-traffic-heading .record-chips", ".dns-traffic-leaders", ".dns-traffic-filters"].forEach((selector) => {
        const currentElement = panel.querySelector(selector);
        const nextElement = nextPanel.querySelector(selector);
        if (currentElement && nextElement) currentElement.replaceWith(nextElement);
      });
      currentTable.tBodies[0].replaceWith(nextTable.tBodies[0]);
      Array.from(currentTable.tHead.rows[0].cells).forEach((header, index) => {
        Array.from(currentTable.tBodies[0].rows).forEach((row) => {
          if (row.cells[index]) row.cells[index].hidden = header.hidden;
        });
      });
      panel.querySelectorAll(".table-settings-panel .table-filter input").forEach((input) => {
        input.dispatchEvent(new Event("input"));
      });
      const currentPagination = panel.querySelector(":scope > .pagination");
      const nextPagination = nextPanel.querySelector(":scope > .pagination");
      if (currentPagination && nextPagination) {
        currentPagination.replaceWith(nextPagination);
      } else if (currentPagination) {
        currentPagination.remove();
      } else if (nextPagination) {
        panel.appendChild(nextPagination);
      }

      if (updateHistory) history.pushState({ dnsTrafficPage: true }, "", url);
      window.scrollTo({ top: scrollTop, left: window.scrollX, behavior: "auto" });
    } catch (error) {
      if (error.name !== "AbortError") console.error(error);
    } finally {
      if (requestController === controller) panel.removeAttribute("aria-busy");
    }
  }

  document.addEventListener("click", (event) => {
    const link = event.target.closest(`${panelSelector} .pagination a, ${panelSelector} .dns-traffic-leaders a, ${panelSelector} .dns-traffic-filters a`);
    if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    refreshTrafficPanel(link.href, true);
  });

  document.addEventListener("submit", (event) => {
    const form = event.target.closest(`${panelSelector} .dns-traffic-filters`);
    if (!form) return;
    event.preventDefault();
    const url = new URL(form.action, window.location.href);
    url.search = new URLSearchParams(new FormData(form)).toString();
    url.hash = "dns-traffic-history";
    refreshTrafficPanel(url.href, true);
  });

  window.addEventListener("popstate", () => {
    if (document.querySelector(panelSelector)) refreshTrafficPanel(window.location.href, false);
  });

  document.addEventListener("toggle", (event) => {
    const menu = event.target;
    if (!(menu instanceof HTMLDetailsElement) || !menu.classList.contains("dns-domain-menu") || !menu.open) return;
    const summary = menu.querySelector("summary");
    const popup = menu.querySelector(".dns-domain-menu-panel");
    if (!summary || !popup) return;

    document.querySelectorAll(".dns-domain-menu[open]").forEach((item) => {
      if (item !== menu) item.open = false;
    });

    requestAnimationFrame(() => {
      const anchor = summary.getBoundingClientRect();
      const popupRect = popup.getBoundingClientRect();
      const margin = 12;
      let left = anchor.left;
      let top = anchor.bottom + 8;
      if (left + popupRect.width > window.innerWidth - margin) left = window.innerWidth - popupRect.width - margin;
      if (top + popupRect.height > window.innerHeight - margin) top = anchor.top - popupRect.height - 8;
      menu.style.setProperty("--dns-popup-left", `${Math.max(margin, left)}px`);
      menu.style.setProperty("--dns-popup-top", `${Math.max(margin, top)}px`);
    });
  }, true);

  document.addEventListener("click", (event) => {
    document.querySelectorAll(".dns-domain-menu[open]").forEach((menu) => {
      if (!menu.contains(event.target)) menu.open = false;
    });
  });
})();
