(() => {
  const gallery = document.querySelector("[data-asset-photo-gallery]");
  if (!gallery) return;
  const main = gallery.querySelector("[data-photo-main]");
  const preview = gallery.querySelector("[data-photo-preview]");
  const thumbnails = [...gallery.querySelectorAll("[data-photo-id]")];
  const primaryForm = document.querySelector("[data-photo-primary-form]");
  const removeForm = document.querySelector("[data-photo-remove-form]");
  const primaryButton = gallery.querySelector("[data-photo-primary-submit]");
  const lightbox = document.querySelector("[data-asset-photo-lightbox]");
  const lightboxImage = lightbox?.querySelector("[data-photo-lightbox-image]");

  const selectPhoto = (button) => {
    if (!main || !button) return;
    const id = button.dataset.photoId;
    main.src = button.dataset.fullSrc;
    main.alt = `${gallery.dataset.assetName || "Asset"} photo`;
    if (preview) preview.dataset.fullSrc = button.dataset.fullSrc;
    thumbnails.forEach((item) => {
      const selected = item === button;
      item.classList.toggle("is-selected", selected);
      item.setAttribute("aria-current", selected ? "true" : "false");
    });
    const assetId = gallery.dataset.assetId;
    if (primaryForm) primaryForm.action = `/infrastructure/asset-manager/${assetId}/photos/${id}/primary`;
    if (removeForm) removeForm.action = `/infrastructure/asset-manager/${assetId}/photos/${id}/delete`;
    if (primaryButton) primaryButton.hidden = button.dataset.isPrimary === "1";
  };

  thumbnails.forEach((button, index) => {
    button.addEventListener("click", () => selectPhoto(button));
    if (index === 0) selectPhoto(button);
  });
  preview?.addEventListener("click", () => {
    if (!lightbox || !lightboxImage) return;
    lightboxImage.src = preview.dataset.fullSrc;
    lightboxImage.alt = `Larger photo of ${gallery.dataset.assetName || "asset"}`;
    if (typeof lightbox.showModal === "function") lightbox.showModal();
    else lightbox.setAttribute("open", "");
  });
  lightbox?.addEventListener("click", (event) => {
    if (event.target === lightbox) lightbox.close?.();
  });
})();

(() => {
  const page = document.querySelector("[data-asset-page]");
  if (!page) return;
  const tabs = [...page.querySelectorAll("[data-asset-tab]")];
  const panels = new Map([...page.querySelectorAll("[data-asset-panel]")].map((panel) => [panel.dataset.assetPanel, panel]));
  const names = tabs.map((tab) => tab.dataset.assetTab);

  // Tabs: one selected tab, roving focus, active tab kept in ?tab= for reloads and links.
  const activate = (name, { focus = false, updateUrl = true } = {}) => {
    if (!panels.has(name)) name = "overview";
    tabs.forEach((tab) => {
      const selected = tab.dataset.assetTab === name;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
      tab.tabIndex = selected ? 0 : -1;
      if (selected && focus) tab.focus();
    });
    panels.forEach((panel, key) => { panel.hidden = key !== name; });
    if (updateUrl) {
      const url = new URL(window.location.href);
      if (name === "overview") url.searchParams.delete("tab"); else url.searchParams.set("tab", name);
      url.hash = "";
      window.history.replaceState(null, "", url);
    }
  };
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => activate(tab.dataset.assetTab));
    tab.addEventListener("keydown", (event) => {
      const moves = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 };
      if (!(event.key in moves)) return;
      event.preventDefault();
      const next = (moves[event.key] + tabs.length) % tabs.length;
      activate(names[next], { focus: true });
    });
  });
  const reveal = (name, targetId) => {
    activate(name);
    const target = targetId && document.getElementById(targetId);
    if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const requested = new URLSearchParams(window.location.search).get("tab");
  const hashTarget = window.location.hash ? document.getElementById(decodeURIComponent(window.location.hash.slice(1))) : null;
  const hashPanel = hashTarget?.closest("[data-asset-panel]")?.dataset.assetPanel;
  activate(requested && panels.has(requested) ? requested : hashPanel || "overview", { updateUrl: false });
  if (hashTarget && hashPanel) hashTarget.scrollIntoView({ block: "start" });

  page.querySelectorAll("[data-asset-tab-target]").forEach((button) => {
    button.addEventListener("click", () => reveal(button.dataset.assetTabTarget, button.dataset.assetScroll));
  });

  // Every "+ Add", "Edit notes" and "Add purchase details" uses the existing inline Edit.
  const editForm = page.querySelector("[data-inline-edit]");
  const editToggle = editForm?.querySelector("[data-edit-toggle]");
  page.querySelectorAll("[data-asset-edit-field]").forEach((button) => {
    button.addEventListener("click", () => {
      if (!editToggle) return;
      activate("overview");
      if (!editForm.classList.contains("is-editing")) editToggle.click();
      const field = editForm.querySelector(`[data-edit][name="${CSS.escape(button.dataset.assetEditField)}"]`);
      if (field && !field.disabled) { field.focus(); field.scrollIntoView({ block: "center" }); }
    });
  });
  editToggle?.addEventListener("click", () => activate("overview"));

  // Photo and attachment uploads open the existing file inputs in the Files tab.
  const openPicker = (selector) => {
    activate("files");
    const input = page.querySelector(selector);
    if (input) { input.scrollIntoView({ block: "center" }); input.click(); }
  };
  page.querySelector("[data-asset-photo-add]")?.addEventListener("click", () => openPicker("#asset-photo-file"));
  page.querySelector("[data-asset-upload-file]")?.addEventListener("click", () => openPicker("[data-asset-attachment-input]"));

  // More actions menu: closes on Escape and outside clicks.
  const menu = page.querySelector("[data-asset-menu]");
  if (menu) {
    menu.addEventListener("toggle", () => { if (menu.open) menu.querySelector("[role=menuitem]")?.focus(); });
    document.addEventListener("click", (event) => { if (menu.open && !menu.contains(event.target)) menu.open = false; });
    menu.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && menu.open) { menu.open = false; menu.querySelector("summary")?.focus(); }
    });
  }

  // Warranty countdown from the stored expiry date and today's date.
  const countdown = page.querySelector("[data-warranty-countdown]");
  if (countdown) {
    const [year, month, day] = countdown.dataset.warrantyDate.split("-").map(Number);
    const today = new Date();
    const days = Math.round((Date.UTC(year, month - 1, day) - Date.UTC(today.getFullYear(), today.getMonth(), today.getDate())) / 86400000);
    if (Number.isFinite(days)) {
      countdown.textContent = days > 0 ? `Warranty expires in ${days} day${days === 1 ? "" : "s"}` : days === 0 ? "Warranty expires today" : `Warranty expired ${-days} day${days === -1 ? "" : "s"} ago`;
    }
  }
})();
