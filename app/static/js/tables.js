(function () {
  const storagePrefix = "kaya.table.columns.";
  const excludedColumnKeys = new Set(["actions", "action", "select", "selection"]);

  function cellValue(row, index) {
    return (row.cells[index]?.textContent || "").trim().toLowerCase();
  }

  function columnKey(header, index) {
    return header.dataset.col || String(index);
  }

  function exportableColumn(header, index) {
    const key = columnKey(header, index).toLowerCase();
    const label = (header.dataset.label || header.textContent || "").trim();
    return header.dataset.export !== "false"
      && !excludedColumnKeys.has(key)
      && !header.classList.contains("action-col")
      && Boolean(label);
  }

  function applyVisibility(table, hiddenColumns) {
    const headers = Array.from(table.tHead.rows[0].cells);
    headers.forEach((header, index) => {
      const hidden = hiddenColumns.has(columnKey(header, index));
      header.hidden = hidden;
      Array.from(table.tBodies).forEach((body) => {
        Array.from(body.rows).forEach((row) => {
          if (row.cells[index]) row.cells[index].hidden = hidden;
        });
      });
    });
  }

  function sortTable(table, index, direction) {
    const body = table.tBodies[0];
    const rows = Array.from(body.rows);
    rows.sort((left, right) => {
      const leftValue = cellValue(left, index);
      const rightValue = cellValue(right, index);
      const leftNumber = Number(leftValue);
      const rightNumber = Number(rightValue);
      if (!Number.isNaN(leftNumber) && !Number.isNaN(rightNumber)) {
        return direction * (leftNumber - rightNumber);
      }
      return direction * leftValue.localeCompare(rightValue, undefined, { numeric: true });
    });
    rows.forEach((row) => body.appendChild(row));
  }

  function applyFilters(table, filters) {
    Array.from(table.tBodies[0].rows).forEach((row) => {
      row.hidden = !filters.every((filter) => !filter.value || cellValue(row, filter.index).includes(filter.value));
    });
  }

  function readableCellValue(cell) {
    if (!cell) return "";
    const copy = cell.cloneNode(true);
    copy.querySelectorAll("script,style,button,.button,.icon-button,[aria-hidden=true]").forEach((node) => node.remove());
    copy.querySelectorAll("input,textarea,select").forEach((control) => {
      let value = "";
      if (control.matches("select")) value = control.selectedOptions[0]?.textContent || "";
      else if (control.type === "checkbox" || control.type === "radio") value = control.checked ? "Yes" : "No";
      else if (control.type !== "hidden" && control.type !== "password") value = control.value || "";
      control.replaceWith(document.createTextNode(value));
    });
    copy.querySelectorAll("img").forEach((image) => image.replaceWith(document.createTextNode(image.alt || "")));
    return (copy.textContent || "").replace(/\u00a0/g, " ").replace(/[ \t]+\n/g, "\n").trim();
  }

  function isEmptyStateRow(row, columnCount) {
    return row.cells.length === 1 && Number(row.cells[0].colSpan || 1) >= columnCount;
  }

  function tableDataset(table, headers, hiddenColumns) {
    const columns = headers
      .map((header, index) => ({ header, index, key: columnKey(header, index) }))
      .filter(({ header, key, index }) => exportableColumn(header, index) && !hiddenColumns.has(key));
    const rows = Array.from(table.tBodies).flatMap((body) => Array.from(body.rows))
      .filter((row) => !row.hidden && !isEmptyStateRow(row, headers.length))
      .map((row) => columns.map(({ index }) => readableCellValue(row.cells[index])));
    return {
      columns: columns.map(({ key, header }) => ({ key, label: (header.dataset.label || header.textContent || "").trim() })),
      rows,
    };
  }

  function safeCsvValue(value) {
    const text = value == null ? "" : String(value);
    return /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  }

  function delimitedContent(dataset, format) {
    const delimiter = format === "csv" ? "," : "\t";
    const quote = (value) => {
      const text = format === "csv" ? safeCsvValue(value) : (value == null ? "" : String(value));
      return format === "csv" ? `"${text.replace(/"/g, '""')}"` : text.replace(/[\t\r\n]+/g, " ");
    };
    return [dataset.columns.map(({ label }) => quote(label)), ...dataset.rows.map((row) => row.map(quote))]
      .map((row) => row.join(delimiter)).join("\r\n") + "\r\n";
  }

  function safeTableName(value) {
    const cleaned = String(value || "table").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    return cleaned || "table";
  }

  function localDate() {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
  }

  function downloadBlob(content, filename, type) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  function announce(message, isError = false) {
    let region = document.querySelector("[data-table-export-status]");
    if (!region) {
      region = document.createElement("div");
      region.dataset.tableExportStatus = "";
      region.className = "table-export-status";
      region.setAttribute("role", isError ? "alert" : "status");
      region.setAttribute("aria-live", "polite");
      document.body.appendChild(region);
    }
    region.setAttribute("role", isError ? "alert" : "status");
    region.textContent = message;
    region.classList.toggle("is-error", isError);
    region.hidden = false;
    clearTimeout(region._hideTimer);
    region._hideTimer = setTimeout(() => { region.hidden = true; }, 3500);
  }

  function endpointUrl(table, format, dataset, filters) {
    const url = new URL(table.dataset.exportUrl, location.href);
    const current = new URLSearchParams(location.search);
    current.delete("page");
    current.delete("per_page");
    current.forEach((value, key) => { if (!url.searchParams.has(key)) url.searchParams.append(key, value); });
    url.searchParams.set("format", format);
    url.searchParams.set("columns", dataset.columns.map(({ key }) => key).join(","));
    const activeFilters = Object.fromEntries(filters.filter(({ value }) => value).map(({ key, value }) => [key, value]));
    if (Object.keys(activeFilters).length) url.searchParams.set("filters", JSON.stringify(activeFilters));
    const activeSort = table.tHead.querySelector("[data-direction]");
    if (activeSort) {
      url.searchParams.set("sort", activeSort.dataset.exportSort || activeSort.dataset.col || "");
      url.searchParams.set("direction", activeSort.dataset.direction);
    }
    return url;
  }

  async function exportTable(table, headers, hiddenColumns, filters, format, menu) {
    if (menu.dataset.loading === "true") return;
    menu.dataset.loading = "true";
    menu.querySelector("summary").setAttribute("aria-busy", "true");
    menu.querySelectorAll("button").forEach((button) => { button.disabled = true; });
    const dataset = tableDataset(table, headers, hiddenColumns);
    try {
      if (table.dataset.exportUrl) {
        const response = await fetch(endpointUrl(table, format, dataset, filters), { credentials: "same-origin", headers: { Accept: format === "csv" ? "text/csv" : "text/plain" } });
        if (!response.ok) throw new Error("The export could not be prepared.");
        const disposition = response.headers.get("Content-Disposition") || "";
        const filenameMatch = disposition.match(/filename="?([^";]+)"?/i);
        const filename = filenameMatch?.[1] || `kaya-${safeTableName(table.dataset.exportName || table.dataset.tableKey)}-${localDate()}.${format === "csv" ? "csv" : "txt"}`;
        downloadBlob(await response.blob(), filename, response.headers.get("Content-Type") || "application/octet-stream");
      } else {
        const extension = format === "csv" ? "csv" : "txt";
        const filename = `kaya-${safeTableName(table.dataset.exportName || table.dataset.tableKey || "table")}-${localDate()}.${extension}`;
        const content = delimitedContent(dataset, format);
        downloadBlob(format === "csv" ? `\ufeff${content}` : content, filename, format === "csv" ? "text/csv;charset=utf-8" : "text/plain;charset=utf-8");
      }
      announce(`${format.toUpperCase()} export downloaded.`);
      menu.open = false;
    } catch (error) {
      announce(error.message || "The export could not be prepared.", true);
    } finally {
      menu.dataset.loading = "false";
      menu.querySelector("summary").removeAttribute("aria-busy");
      menu.querySelectorAll("button").forEach((button) => { button.disabled = false; });
    }
  }

  document.querySelectorAll(".content table").forEach((table, tableIndex) => {
    if (!table.tHead || !table.tBodies.length) return;
    if (table.closest("#checks") && /\/networking\/ip-wan-monitor\/\d+$/.test(location.pathname)) {
      table.dataset.tableKey = "network-monitor-checks";
      table.dataset.exportUrl = `${location.pathname}/checks.csv`;
      ["timestamp", "status", "latency", "packet-loss", "response", "failure-reason"].forEach((name, index) => {
        if (table.tHead.rows[0].cells[index]) table.tHead.rows[0].cells[index].dataset.col = name;
      });
    }
    const key = table.dataset.tableKey || `${location.pathname}.${tableIndex}`;
    table.dataset.tableKey = key;
    const storageKey = storagePrefix + key;
    const headers = Array.from(table.tHead.rows[0].cells);
    const parent = table.parentNode;
    let hiddenColumns;
    try { hiddenColumns = new Set(JSON.parse(localStorage.getItem(storageKey) || "[]")); }
    catch { hiddenColumns = new Set(); }
    const toolbar = document.createElement("div");
    const filters = [];
    toolbar.className = "table-toolbar";
    toolbar.innerHTML = '<details class="table-settings"><summary>Table settings</summary><div class="table-settings-panel"></div></details>';
    const settings = toolbar.querySelector(".table-settings");
    const panel = toolbar.querySelector(".table-settings-panel");
    const tableFilters = parent.querySelector(":scope > .table-panel-filters");
    if (tableFilters) { toolbar.classList.add("has-filters"); toolbar.prepend(tableFilters); }

    headers.forEach((header, index) => {
      const keyName = columnKey(header, index);
      const label = header.dataset.label || header.textContent.trim() || "Actions";
      if (header.dataset.sort !== undefined) {
        header.classList.add("sortable");
        header.tabIndex = 0;
        header.addEventListener("click", () => {
          const nextDirection = header.dataset.direction === "asc" ? -1 : 1;
          headers.forEach((item) => item.removeAttribute("data-direction"));
          header.dataset.direction = nextDirection === 1 ? "asc" : "desc";
          sortTable(table, index, nextDirection);
        });
        header.addEventListener("keydown", (event) => {
          if (event.key === "Enter" || event.key === " ") { event.preventDefault(); header.click(); }
        });
      }
      const option = document.createElement("label");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = keyName;
      option.append(checkbox, document.createTextNode(` ${label}`));
      checkbox.checked = !hiddenColumns.has(keyName);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) hiddenColumns.delete(keyName); else hiddenColumns.add(keyName);
        localStorage.setItem(storageKey, JSON.stringify(Array.from(hiddenColumns)));
        applyVisibility(table, hiddenColumns);
      });
      panel.appendChild(option);
      if (!excludedColumnKeys.has(keyName) && label) {
        const filterLabel = document.createElement("label");
        filterLabel.className = "table-filter";
        const filterInput = document.createElement("input");
        filterInput.type = "search";
        filterInput.placeholder = `Filter ${label}`;
        const filter = { index, key: keyName, value: "" };
        filters.push(filter);
        filterInput.addEventListener("input", () => { filter.value = filterInput.value.trim().toLowerCase(); applyFilters(table, filters); });
        filterLabel.appendChild(filterInput);
        panel.appendChild(filterLabel);
      }
    });

    const protectedTable = location.pathname === "/admin"
      || key === "secret-vault-items" || key === "about-sessions"
      || table.classList.contains("secure-send-table")
      || Boolean(table.querySelector('form[action*="/authentication/links/"]'));
    if (!protectedTable && table.dataset.export !== "false" && headers.some(exportableColumn)) {
      const exportMenu = document.createElement("details");
      exportMenu.className = "table-export";
      exportMenu.innerHTML = '<summary aria-label="Export table" title="Export the current table" aria-haspopup="menu"><span aria-hidden="true">⇩</span> Export</summary><div class="table-export-panel" role="menu"><button type="button" role="menuitem" data-table-export-format="csv">Export as CSV</button><button type="button" role="menuitem" data-table-export-format="text">Export as Text</button></div>';
      exportMenu.querySelectorAll("button").forEach((button) => button.addEventListener("click", () => void exportTable(table, headers, hiddenColumns, filters, button.dataset.tableExportFormat, exportMenu)));
      exportMenu.querySelector(".table-export-panel").addEventListener("keydown", (event) => {
        const items = Array.from(event.currentTarget.querySelectorAll("button:not(:disabled)"));
        const index = items.indexOf(document.activeElement);
        if (["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) {
          event.preventDefault();
          const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : (index + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
          items[next]?.focus();
        }
      });
      exportMenu.addEventListener("toggle", () => {
        if (!exportMenu.open) return;
        const exportPanel = exportMenu.querySelector(".table-export-panel");
        if (window.innerWidth > 850) {
          const trigger = exportMenu.querySelector("summary").getBoundingClientRect();
          const width = exportPanel.offsetWidth || 180;
          exportPanel.style.left = `${Math.max(12, Math.min(trigger.right - width, window.innerWidth - width - 12))}px`;
          exportPanel.style.top = `${Math.min(trigger.bottom + 6, window.innerHeight - exportPanel.offsetHeight - 12)}px`;
          exportPanel.style.right = "auto";
        } else {
          exportPanel.removeAttribute("style");
        }
        exportMenu.querySelector("button")?.focus();
      });
      toolbar.insertBefore(exportMenu, settings);
    }

    const toolbarHost = parent.querySelector(":scope > [data-table-toolbar-host]");
    if (toolbarHost) toolbarHost.appendChild(toolbar); else parent.insertBefore(toolbar, table);
    if (!table.closest(".table-scroll")) {
      const scrollWrap = document.createElement("div");
      scrollWrap.className = "table-scroll";
      scrollWrap.tabIndex = 0;
      scrollWrap.setAttribute("role", "region");
      scrollWrap.setAttribute("aria-label", `${key.replace(/[._-]+/g, " ")} table; scroll horizontally for more columns`);
      parent.insertBefore(scrollWrap, table);
      scrollWrap.appendChild(table);
    }
    applyVisibility(table, hiddenColumns);
    applyFilters(table, filters);
  });

  const closeMenus = (except = null) => {
    document.querySelectorAll(".table-settings[open],.table-export[open]").forEach((menu) => { if (menu !== except) menu.open = false; });
  };
  document.addEventListener("toggle", (event) => {
    const menu = event.target.closest(".table-settings,.table-export");
    if (menu?.open) closeMenus(menu);
  }, true);
  document.addEventListener("click", (event) => { if (!event.target.closest(".table-settings,.table-export")) closeMenus(); });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") { closeMenus(); document.activeElement?.blur(); } });
})();
