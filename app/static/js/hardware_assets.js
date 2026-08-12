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
