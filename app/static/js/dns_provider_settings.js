(() => {
  const root = document.querySelector("[data-dns-provider-settings]");
  const mode = root?.querySelector("[data-dns-connection-mode]");
  if (!root || !mode) return;
  const update = () => {
    const clustered = mode.value === "ha_cluster";
    root.querySelectorAll("[data-dns-ha-field]").forEach((field) => {
      field.hidden = !clustered;
      field.querySelectorAll("input, select").forEach((input) => { input.disabled = !clustered; });
    });
    root.querySelectorAll("[data-dns-standalone-field]").forEach((field) => {
      field.hidden = clustered;
      field.querySelectorAll("input, select").forEach((input) => { input.disabled = clustered; });
    });
  };
  mode.addEventListener("change", update);
  update();
})();
