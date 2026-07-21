(() => {
  const root = document.querySelector("[data-settings-tabs]");
  if (!root) return;

  const parentTabs = Array.from(root.querySelectorAll("[data-settings-parent-tab]"));
  const childTabs = Array.from(root.querySelectorAll("[data-settings-child-tab]"));
  const childTabRow = root.querySelector("[data-settings-subtabs]");
  const detailGroups = Array.from(root.querySelectorAll("[data-settings-details]"));
  const panels = Array.from(root.querySelectorAll("[data-settings-panel]"));
  const storageKey = root.dataset.settingsStorageKey || "kaya.siteAdministration.activeTab";

  root.querySelectorAll(".vlan-ip-toggle .remote-switch").forEach((toggle) => {
    const label = toggle.closest(".vlan-ip-toggle")?.querySelector("span");
    const update = () => {
      if (label) label.textContent = toggle.checked ? "Enabled" : "Disabled";
    };
    toggle.addEventListener("change", update);
    update();
  });

  const panelKeys = new Set(panels.map((panel) => panel.dataset.settingsPanel || "").filter(Boolean));
  const childrenByParent = new Map();
  childTabs.forEach((tab) => {
    const parent = tab.dataset.settingsParent || "";
    const key = tab.dataset.settingsChildTab || "";
    if (!parent || !key) return;
    if (!childrenByParent.has(parent)) childrenByParent.set(parent, []);
    childrenByParent.get(parent).push(key);
  });

  const tabAliases = {
    backups: "module-backup-manager",
    "backup-manager": "module-backup-manager",
    modules: "module-backup-manager",
    module: "module-backup-manager",
    "dns-manager": "module-dns-manager",
    dns: "module-dns-manager",
    "remote-manager": "module-remote-manager",
    remote: "module-remote-manager",
    remote_manager: "module-remote-manager",
    email: "email-general",
    templates: "email-templates",
    "email_templates": "email-templates",
    "email-template": "email-templates",
  };

  const normaliseRequestedTab = (value) => {
    const clean = String(value || "").trim().toLowerCase();
    if (!clean) return "";
    const mapped = tabAliases[clean] || clean;
    return panelKeys.has(mapped) ? mapped : "";
  };

  const updateQueryTab = (panelKey) => {
    if (!panelKey) return;
    try {
      const url = new URL(window.location.href);
      url.searchParams.set("tab", panelKey);
      window.history.replaceState({}, "", url.toString());
    } catch {
      // Ignore URL update failures in restricted contexts.
    }
  };

  const readStoredTab = () => {
    const requested = normaliseRequestedTab(new URLSearchParams(window.location.search).get("tab"));
    if (requested) return requested;
    try {
      return normaliseRequestedTab(window.localStorage.getItem(storageKey));
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

  const defaultPanelForParent = (parentKey) => {
    const parentTab = parentTabs.find((tab) => tab.dataset.settingsParentTab === parentKey);
    const preferred = parentTab?.dataset.defaultChild || "";
    if (preferred && panelKeys.has(preferred)) return preferred;
    const children = childrenByParent.get(parentKey) || [];
    if (children.length && panelKeys.has(children[0])) return children[0];
    if (panelKeys.has(parentKey)) return parentKey;
    return panels[0]?.dataset.settingsPanel || "";
  };

  const parentForPanel = (panelKey) => {
    const panel = panels.find((item) => item.dataset.settingsPanel === panelKey);
    if (panel?.dataset.settingsParent) return panel.dataset.settingsParent;
    const childTab = childTabs.find((tab) => tab.dataset.settingsChildTab === panelKey);
    return childTab?.dataset.settingsParent || panelKey;
  };

  const activate = (panelKey) => {
    const fallback = defaultPanelForParent(parentTabs[0]?.dataset.settingsParentTab || "");
    const activePanel = panelKeys.has(panelKey) ? panelKey : fallback;
    const activeParent = parentForPanel(activePanel);
    const activeChildren = childrenByParent.get(activeParent) || [];

    parentTabs.forEach((tab) => {
      const parentKey = tab.dataset.settingsParentTab;
      const active = parentKey === activeParent;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("aria-current", active ? "page" : "false");
    });

    detailGroups.forEach((group) => {
      if (group.dataset.settingsDetails === activeParent) {
        group.open = true;
      }
    });

    if (childTabRow) {
      const showChildren = activeChildren.length > 0;
      childTabRow.hidden = !showChildren;
      childTabRow.classList.toggle("active", showChildren);
    }

    childTabs.forEach((tab) => {
      const visible = tab.dataset.settingsParent === activeParent;
      const active = visible && tab.dataset.settingsChildTab === activePanel;
      if (childTabRow) tab.hidden = !visible;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.setAttribute("aria-current", active ? "page" : "false");
    });

    panels.forEach((panel) => {
      const active = panel.dataset.settingsPanel === activePanel;
      panel.hidden = !active;
      panel.classList.toggle("active", active);
    });

    if (activePanel) {
      writeStoredTab(activePanel);
      updateQueryTab(activePanel);
    }
  };

  parentTabs.forEach((tab) => {
    tab.addEventListener("click", (event) => {
      const parentKey = tab.dataset.settingsParentTab || "";
      const group = tab.closest("details");
      const wasActive = tab.classList.contains("active");
      const wasOpen = Boolean(group?.open);
      if (tab.tagName === "SUMMARY" || tab.tagName === "A") {
        event.preventDefault();
      }
      activate(defaultPanelForParent(parentKey));
      if (group) {
        group.open = wasActive ? !wasOpen : true;
      }
    });
  });

  childTabs.forEach((tab) => {
    tab.addEventListener("click", (event) => {
      if (tab.tagName === "A") {
        event.preventDefault();
      }
      activate(tab.dataset.settingsChildTab || "");
    });
  });

  const publicIpButton = root.querySelector("[data-public-ip-check]");
  const publicIpResult = root.querySelector("[data-public-ip-result]");
  const publicIpDetail = root.querySelector("[data-public-ip-detail]");
  if (publicIpButton && publicIpResult && publicIpDetail) {
    publicIpButton.addEventListener("click", async () => {
      publicIpButton.disabled = true;
      publicIpResult.textContent = "Checking...";
      publicIpDetail.textContent = "Kaya is asking an external IP service from the server.";
      try {
        const response = await fetch("/system/site-administration/security/public-ip", {
          headers: { Accept: "application/json" },
        });
        const data = await response.json();
        if (!response.ok || !data.ok) {
          throw new Error(data.error || "Public IP check failed");
        }
        publicIpResult.textContent = data.ip;
        publicIpDetail.textContent = `Reported by ${data.source}. This is Kaya's outbound public IP.`;
      } catch (error) {
        publicIpResult.textContent = "Unavailable";
        publicIpDetail.textContent = error.message || "Kaya could not reach a public IP service.";
      } finally {
        publicIpButton.disabled = false;
      }
    });
  }

  const inboundButton = root.querySelector("[data-inbound-check]");
  const inboundResult = root.querySelector("[data-inbound-result]");
  const inboundDetail = root.querySelector("[data-inbound-detail]");
  if (inboundButton && inboundResult && inboundDetail) {
    inboundButton.addEventListener("click", async () => {
      inboundButton.disabled = true;
      inboundResult.textContent = "Checking...";
      inboundDetail.textContent = "Kaya is resolving the hostname used by this browser request.";
      try {
        const response = await fetch("/system/site-administration/security/inbound", {
          headers: { Accept: "application/json" },
        });
        const data = await response.json();
        if (!response.ok || !data.ok) {
          throw new Error(data.error || "Inbound DNS check failed");
        }
        inboundResult.textContent = data.addresses.join(", ");
        inboundDetail.textContent = `Resolved ${data.host}. This is where browsers are routed before reaching Kaya.`;
      } catch (error) {
        inboundResult.textContent = "Unavailable";
        inboundDetail.textContent = error.message || "Kaya could not resolve the inbound hostname.";
      } finally {
        inboundButton.disabled = false;
      }
    });
  }

  const hostHardening = root.querySelector("[data-host-hardening]");
  if (hostHardening) {
    const toggle = hostHardening.querySelector('input[name="trusted_hosts_enabled"]');
    const field = hostHardening.querySelector('textarea[name="allowed_hosts"]');
    const statusBox = hostHardening.querySelector("[data-current-host-status]");
    const statusMessage = hostHardening.querySelector("[data-host-status-message]");
    const warning = hostHardening.querySelector("[data-host-lockout-warning]");
    const errors = hostHardening.querySelector("[data-host-errors]");
    const currentHost = String(hostHardening.dataset.currentHost || "").trim();

    const hostWithoutPort = (value) => {
      const host = String(value || "").trim().toLowerCase();
      if (host.startsWith("[")) return host.slice(1).split("]", 1)[0];
      return (host.match(/:/g) || []).length === 1 ? host.slice(0, host.lastIndexOf(":")) : host;
    };
    const matches = (host, pattern) => {
      const cleanHost = hostWithoutPort(host);
      const cleanPattern = hostWithoutPort(pattern);
      if (cleanPattern === "*") return true;
      if (cleanPattern.startsWith("*.")) {
        const suffix = cleanPattern.slice(1);
        return cleanHost.endsWith(suffix) && cleanHost !== cleanPattern.slice(2);
      }
      return cleanHost === cleanPattern;
    };
    const invalidEntryMessage = (entry) => {
      if (entry.includes("://")) return "Enter only the hostname or IP address, without http:// or https://.";
      if (entry === "*") return "";
      const candidate = entry.startsWith("[") && entry.endsWith("]") ? entry.slice(1, -1) : entry;
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(candidate)) {
        return candidate.split(".").every((part) => Number(part) <= 255) ? "" : "Enter a valid IPv4 address.";
      }
      if (candidate.includes(":") && /^[0-9a-f:]+$/i.test(candidate)) return "";
      const hostname = candidate.startsWith("*.") ? candidate.slice(2) : candidate;
      if (hostname.includes("*")) return "A wildcard is only supported at the start of a domain, for example *.example.com.";
      if (!hostname.includes(".")) return "Enter a fully qualified hostname, such as kaya.example.com, or an IP address.";
      const valid = hostname.replace(/\.$/, "").split(".").every((label) =>
        /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label));
      return valid ? "" : "Use letters, numbers and hyphens in each hostname label.";
    };
    const updateHostStatus = () => {
      const enabled = Boolean(toggle?.checked);
      const entries = String(field?.value || "").split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
      const allowed = entries.some((entry) => matches(currentHost, entry));
      statusBox?.classList.toggle("is-allowed", enabled && allowed);
      statusBox?.classList.toggle("is-warning", enabled && !allowed);
      if (statusMessage) {
        statusMessage.textContent = !enabled
          ? "Host validation is currently inactive."
          : allowed ? "Current host is allowed" : "Current host is not included in the allow list.";
      }
      if (warning) warning.hidden = !enabled || allowed;
    };
    toggle?.addEventListener("change", updateHostStatus);
    field?.addEventListener("input", () => {
      updateHostStatus();
      field.setAttribute("aria-invalid", "false");
      field.closest("label")?.classList.remove("field-invalid");
      if (errors) errors.replaceChildren();
    });
    root.addEventListener("submit", (event) => {
      // Panel-specific actions validate their own fields server-side. Do not let
      // an unrelated hidden settings panel prevent those requests from running.
      if (event.submitter?.formNoValidate) return;
      const value = String(field?.value || "");
      const entryErrors = [];
      value.split(/\r?\n/).forEach((line, index) => {
        line.split(",").map((item) => item.trim()).filter(Boolean).forEach((entry) => {
          const message = invalidEntryMessage(entry);
          if (message) entryErrors.push(`<p><strong>Line ${index + 1} — ${entry.replace(/[&<>"]/g, "")}</strong>: ${message}</p>`);
        });
      });
      if (toggle?.checked && !value.trim()) {
        entryErrors.unshift("<p>Host restriction is enabled but no allowed hosts have been configured. At least one hostname or IP address must be added before this setting can be enabled.</p>");
      }
      if (!entryErrors.length) return;
      event.preventDefault();
      field.setAttribute("aria-invalid", "true");
      field.closest("label")?.classList.add("field-invalid");
      if (errors) errors.innerHTML = entryErrors.join("");
      activate("security");
      field.focus();
    });
    updateHostStatus();
  }

  const builder = root.querySelector("[data-backup-targets-builder]");
  if (builder) {
    const list = builder.querySelector("[data-backup-targets-list]");
    const editor = builder.querySelector("[data-backup-target-editor]");
    const addButton = builder.querySelector("[data-add-backup-target]");
    const targetsField = root.querySelector("#backup_targets_json");
    const defaultField = root.querySelector("#backup_default_target_name");
    const legacyType = root.querySelector("#backup_storage_type");
    const legacyPath = root.querySelector("#backup_storage_path");
    const legacyHost = root.querySelector("#backup_remote_host");
    const legacyShare = root.querySelector("#backup_remote_share");
    const legacyUsername = root.querySelector("#backup_remote_username");
    const csrf = root.querySelector('input[name="csrf_token"]')?.value || "";

    let targets = [];
    let editIndex = -1;

    const safeParse = (value) => {
      try {
        const parsed = JSON.parse(value || "[]");
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    };

    const normalizeType = (value) => {
      const clean = String(value || "local").trim().toLowerCase();
      return ["local", "smb", "ftp", "sftp"].includes(clean) ? clean : "local";
    };

    const text = (value) => String(value || "");
    const esc = (value) => text(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");

    const normalizeTarget = (target = {}, index = 0) => {
      const name = text(target.name || target.target_name || target.label).trim() || `Target ${index + 1}`;
      return {
        name,
        type: normalizeType(target.type || target.storage_type || "local"),
        path: text(target.path || target.storage_path || "").trim(),
        remote_host: text(target.remote_host || target.host || "").trim(),
        remote_share: text(target.remote_share || target.share || "").trim(),
        remote_username: text(target.remote_username || target.username || "").trim(),
        remote_password: "",
        remote_password_enc: text(target.remote_password_enc || "").trim(),
      };
    };

    const createInput = (name, value) => {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      return input;
    };

    const submitTestForTarget = (target) => {
      const post = document.createElement("form");
      post.method = "post";
      post.action = "/system/site-administration/test-backup-storage";
      post.appendChild(createInput("csrf_token", csrf));
      post.appendChild(createInput("backup_storage_type", target.type));
      post.appendChild(createInput("backup_storage_path", target.path));
      post.appendChild(createInput("backup_remote_host", target.remote_host));
      post.appendChild(createInput("backup_remote_share", target.remote_share));
      post.appendChild(createInput("backup_remote_username", target.remote_username));
      post.appendChild(createInput("backup_remote_password", target.remote_password || ""));
      post.appendChild(createInput("backup_remote_password_enc", target.remote_password_enc || ""));
      post.appendChild(createInput("backup_targets_json", targetsField.value));
      post.appendChild(createInput("backup_default_target_name", defaultField.value));
      post.style.display = "none";
      document.body.appendChild(post);
      post.submit();
    };

    const renderTable = () => {
      if (!targets.length) {
        list.innerHTML = '<div class="backup-target-empty muted">No backup targets saved yet.</div>';
        return;
      }

      const table = document.createElement("table");
      table.className = "backup-target-table";
      table.innerHTML = `
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Path</th>
            <th>Remote host</th>
            <th>Share/path</th>
            <th>Username</th>
            <th>Default</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody></tbody>
      `;
      const body = table.querySelector("tbody");

      targets.forEach((target, index) => {
        const row = document.createElement("tr");
        const isDefault = target.name === defaultField.value;
        row.innerHTML = `
          <td>${esc(target.name)}</td>
          <td>${esc(target.type.toUpperCase())}</td>
          <td>${esc(target.path || "-")}</td>
          <td>${esc(target.remote_host || "-")}</td>
          <td>${esc(target.remote_share || "-")}</td>
          <td>${esc(target.remote_username || "-")}</td>
          <td><input type="radio" name="backup_target_default_table" ${isDefault ? "checked" : ""} aria-label="Set ${esc(target.name)} as default"></td>
          <td class="backup-target-actions"></td>
        `;

        row.querySelector('input[type="radio"]').addEventListener("change", () => {
          defaultField.value = target.name;
          serialize();
        });

        const actions = row.querySelector(".backup-target-actions");
        const edit = document.createElement("button");
        edit.type = "button";
        edit.className = "button secondary";
        edit.textContent = "Edit";
        edit.addEventListener("click", () => openEditor(index));

        const test = document.createElement("button");
        test.type = "button";
        test.className = "button secondary";
        test.textContent = "Test";
        test.addEventListener("click", () => {
          serialize();
          submitTestForTarget(targets[index]);
        });

        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "button secondary";
        remove.textContent = "Remove";
        remove.addEventListener("click", () => {
          targets.splice(index, 1);
          if (defaultField.value === target.name) {
            defaultField.value = targets[0]?.name || "";
          }
          serialize();
          render();
        });

        actions.append(edit, test, remove);
        body.appendChild(row);
      });

      list.replaceChildren(table);
    };

    const closeEditor = () => {
      editIndex = -1;
      editor.innerHTML = "";
      editor.hidden = true;
      addButton.disabled = false;
    };

    const openEditor = (index = -1) => {
      editIndex = index;
      const source = index >= 0
        ? targets[index]
        : { name: "", type: "local", path: "/mnt/backups", remote_host: "", remote_share: "", remote_username: "", remote_password: "", remote_password_enc: "" };
      const hasSavedPassword = Boolean(source.remote_password_enc);

      editor.innerHTML = `
        <fieldset class="backup-target-form">
          <legend>${index >= 0 ? "Edit backup target" : "New backup target"}</legend>
          <label><strong>Name</strong><input data-edit-field="name" placeholder="NAS SMB" value="${esc(source.name)}"></label>
          <label><strong>Type</strong>
            <select data-edit-field="type">
              <option value="local">Local path</option>
              <option value="smb">SMB</option>
              <option value="ftp">FTP</option>
              <option value="sftp">SFTP</option>
            </select>
          </label>
          <label><strong>Path</strong><input data-edit-field="path" placeholder="/mnt/backups" value="${esc(source.path)}"></label>
          <label><strong>Remote host</strong><input data-edit-field="remote_host" placeholder="backup.example.local" value="${esc(source.remote_host)}"></label>
          <label><strong>Remote share/path</strong><input data-edit-field="remote_share" placeholder="backups" value="${esc(source.remote_share)}"></label>
          <label><strong>Remote username</strong><input data-edit-field="remote_username" placeholder="backup-user" value="${esc(source.remote_username)}"></label>
          <label>
            <strong>Remote password</strong>
            <small>${hasSavedPassword ? "A password is saved for this target. Enter a new one to replace it." : "Optional password for this target."}</small>
            <input data-edit-field="remote_password" type="password" autocomplete="new-password" placeholder="${hasSavedPassword ? "Saved password" : ""}">
          </label>
          <div class="backup-target-form-actions">
            <button type="button" class="button" data-save-target>Save target</button>
            <button type="button" class="button secondary" data-cancel-target>Cancel</button>
          </div>
        </fieldset>
      `;

      editor.querySelector('[data-edit-field="type"]').value = source.type;
      editor.querySelector("[data-cancel-target]").addEventListener("click", closeEditor);
      editor.querySelector("[data-save-target]").addEventListener("click", () => {
        const read = (name) => String(editor.querySelector(`[data-edit-field="${name}"]`)?.value || "").trim();
        const next = {
          name: read("name"),
          type: normalizeType(read("type")),
          path: read("path"),
          remote_host: read("remote_host"),
          remote_share: read("remote_share"),
          remote_username: read("remote_username"),
          remote_password: read("remote_password"),
          remote_password_enc: editIndex >= 0 ? targets[editIndex].remote_password_enc || "" : "",
        };
        if (!next.name) {
          editor.querySelector('[data-edit-field="name"]')?.focus();
          return;
        }

        const duplicate = targets.findIndex((target, idx) => target.name.toLowerCase() === next.name.toLowerCase() && idx !== editIndex);
        if (duplicate !== -1) {
          editor.querySelector('[data-edit-field="name"]')?.focus();
          return;
        }

        if (editIndex >= 0) {
          const oldName = targets[editIndex].name;
          targets[editIndex] = next;
          if (defaultField.value === oldName) defaultField.value = next.name;
        } else {
          targets.push(next);
          if (!defaultField.value) defaultField.value = next.name;
        }

        serialize();
        render();
        closeEditor();
      });

      editor.hidden = false;
      addButton.disabled = true;
      editor.querySelector('[data-edit-field="name"]')?.focus();
    };

    const serialize = () => {
      targetsField.value = JSON.stringify(targets.map((target) => ({
        name: target.name,
        type: target.type,
        path: target.path,
        remote_host: target.remote_host,
        remote_share: target.remote_share,
        remote_username: target.remote_username,
        remote_password: target.remote_password || "",
        remote_password_enc: target.remote_password_enc || "",
      })));

      if (!targets.some((target) => target.name === defaultField.value)) {
        defaultField.value = targets[0]?.name || "";
      }

      const selected = targets.find((target) => target.name === defaultField.value) || targets[0] || null;
      legacyType.value = selected?.type || "local";
      legacyPath.value = selected?.path || "/mnt/backups";
      legacyHost.value = selected?.remote_host || "";
      legacyShare.value = selected?.remote_share || "";
      legacyUsername.value = selected?.remote_username || "";
    };

    const render = () => {
      renderTable();
    };

    const initialTargets = safeParse(targetsField.value);
    targets = initialTargets.length
      ? initialTargets.map((target, index) => normalizeTarget(target, index))
      : [{
        name: "Default",
        type: normalizeType(legacyType.value || "local"),
        path: text(legacyPath.value || "/mnt/backups").trim(),
        remote_host: text(legacyHost.value || "").trim(),
        remote_share: text(legacyShare.value || "").trim(),
        remote_username: text(legacyUsername.value || "").trim(),
        remote_password: "",
        remote_password_enc: "",
      }];

    if (!defaultField.value && targets.length) {
      defaultField.value = targets[0].name;
    }

    addButton?.addEventListener("click", () => openEditor(-1));
    root.addEventListener("submit", serialize);
    serialize();
    render();
  }

  const initial = readStoredTab() || defaultPanelForParent(parentTabs[0]?.dataset.settingsParentTab || "");
  activate(initial);
})();
