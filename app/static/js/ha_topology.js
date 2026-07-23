(() => {
  const form = document.querySelector(".ha-topology-form");
  if (!form) return;
  const managed = form.querySelector("[data-ha-topology-managed]");
  const external = form.querySelector("[data-ha-topology-external]");
  const acknowledgement = managed?.querySelector('input[name="acknowledge_managed_dhcp"]');
  const refresh = () => {
    const isManaged = form.querySelector('input[name="deployment_mode"]:checked')?.value === "DNS_DHCP";
    if (managed) managed.hidden = !isManaged;
    if (external) external.hidden = isManaged;
    if (acknowledgement) acknowledgement.required = isManaged;
  };
  form.querySelectorAll('input[name="deployment_mode"]').forEach((input) => input.addEventListener("change", refresh));
  refresh();
})();
