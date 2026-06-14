(function () {
  const storagePrefix = "homelab.table.columns.";

  function cellValue(row, index) {
    return (row.cells[index]?.textContent || "").trim().toLowerCase();
  }

  function applyVisibility(table, hiddenColumns) {
    const headers = Array.from(table.tHead.rows[0].cells);
    headers.forEach((header, index) => {
      const key = header.dataset.col || String(index);
      const hidden = hiddenColumns.has(key);
      header.hidden = hidden;
      Array.from(table.tBodies).forEach((body) => {
        Array.from(body.rows).forEach((row) => {
          if (row.cells[index]) {
            row.cells[index].hidden = hidden;
          }
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
      const visible = filters.every((filter) => {
        if (!filter.value) {
          return true;
        }
        return cellValue(row, filter.index).includes(filter.value);
      });
      row.hidden = !visible;
    });
  }

  document.querySelectorAll("table[data-table-key]").forEach((table) => {
    const key = table.dataset.tableKey;
    const storageKey = storagePrefix + key;
    const headers = Array.from(table.tHead.rows[0].cells);
    const parent = table.parentNode;
    let hiddenColumns;
    try {
      hiddenColumns = new Set(JSON.parse(localStorage.getItem(storageKey) || "[]"));
    } catch {
      hiddenColumns = new Set();
    }
    const toolbar = document.createElement("div");
    const filters = [];
    toolbar.className = "table-toolbar";
    toolbar.innerHTML = '<details class="table-settings"><summary>Table settings</summary><div class="table-settings-panel"></div></details>';
    const panel = toolbar.querySelector(".table-settings-panel");

    headers.forEach((header, index) => {
      const columnKey = header.dataset.col || String(index);
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
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            header.click();
          }
        });
      }

      const option = document.createElement("label");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = columnKey;
      option.appendChild(checkbox);
      option.appendChild(document.createTextNode(` ${label}`));
      checkbox.checked = !hiddenColumns.has(columnKey);
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) {
          hiddenColumns.delete(columnKey);
        } else {
          hiddenColumns.add(columnKey);
        }
        localStorage.setItem(storageKey, JSON.stringify(Array.from(hiddenColumns)));
        applyVisibility(table, hiddenColumns);
      });
      panel.appendChild(option);

      if (!["actions", "select"].includes(columnKey) && label) {
        const filterLabel = document.createElement("label");
        filterLabel.className = "table-filter";
        const filterInput = document.createElement("input");
        filterInput.type = "search";
        filterInput.placeholder = `Filter ${label}`;
        const filter = { index, value: "" };
        filters.push(filter);
        filterInput.addEventListener("input", () => {
          filter.value = filterInput.value.trim().toLowerCase();
          applyFilters(table, filters);
        });
        filterLabel.appendChild(filterInput);
        panel.appendChild(filterLabel);
      }
    });

    parent.insertBefore(toolbar, table);
    if (!table.closest(".table-scroll")) {
      const scrollWrap = document.createElement("div");
      scrollWrap.className = "table-scroll";
      parent.insertBefore(scrollWrap, table);
      scrollWrap.appendChild(table);
    }
    applyVisibility(table, hiddenColumns);
    applyFilters(table, filters);
  });
})();
