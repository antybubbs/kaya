document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form.ha-wizard");
  if (!form) return;

  const field = (name) => form.elements.namedItem(name);
  const tested = { primary: false, secondary: false };
  const check = (key, ok, message) => {
    const element = form.querySelector(`[data-ha-topology-check="${key}"]`);
    if (!element) return;
    element.className = ok === null ? "" : ok ? "is-pass" : "is-fail";
    element.textContent = `${ok === null ? "○" : ok ? "✓" : "!"} ${message}`;
  };
  const ipv4 = (value) => {
    const parts = String(value || "").trim().split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    return parts.reduce((result, part) => ((result << 8) | part) >>> 0, 0);
  };
  const hostFromUrl = (value) => {
    try { return new URL(value).hostname; } catch (_error) { return ""; }
  };

  const updateMode = () => {
    const mode = field("deployment_mode").value;
    const dnsOnly = mode === "DNS_ONLY";
    const external = form.querySelector("[data-ha-dns-only]");
    external.hidden = !dnsOnly;
    field("external_dhcp_provider").required = dnsOnly;
    form.querySelectorAll("[data-ha-architecture]").forEach((diagram) => { diagram.hidden = diagram.dataset.haArchitecture !== mode; });
    updateTopology();
  };

  const updateTopology = () => {
    const vipText = field("virtual_ip").value.trim();
    const vip = ipv4(vipText);
    const prefix = Number(field("prefix_length").value);
    const primaryHost = hostFromUrl(field("primary_api_base_url").value);
    const secondaryHost = hostFromUrl(field("secondary_api_base_url").value);
    const primary = ipv4(primaryHost);
    const secondary = ipv4(secondaryHost);
    const gateway = ipv4(field("gateway_address").value);
    if (vip !== null && primary !== null && secondary !== null && gateway !== null && prefix >= 1 && prefix <= 32) {
      const mask = prefix === 32 ? 0xffffffff : (0xffffffff << (32 - prefix)) >>> 0;
      const same = (vip & mask) === (primary & mask) && (vip & mask) === (secondary & mask) && (vip & mask) === (gateway & mask);
      check("subnet", same, same ? "Both nodes, the gateway and DNS Virtual IP use the same network." : "The nodes, gateway and DNS Virtual IP must use the same IPv4 network.");
    } else {
      check("subnet", null, "Enter IPv4 node URLs, gateway, DNS Virtual IP and network prefix.");
    }
    let existing = [];
    try { existing = JSON.parse(form.dataset.haExistingVips || "[]"); } catch (_error) { existing = []; }
    check("unique", vip === null ? null : !existing.includes(vipText), vip === null ? "Enter the DNS Virtual IP." : existing.includes(vipText) ? "This DNS Virtual IP is already assigned to another Kaya cluster." : "The DNS Virtual IP is not assigned to another Kaya cluster.");
    check("connections", tested.primary && tested.secondary ? true : null, tested.primary && tested.secondary ? "Both Pi-hole API connections passed." : "Test both Pi-hole API connections before saving.");
    form.querySelectorAll("[data-ha-diagram-vip]").forEach((element) => { element.textContent = vipText ? `Primary DNS · ${vipText}` : "Primary DNS · Virtual IP"; });
    form.querySelectorAll("[data-ha-diagram-secondary]").forEach((element) => { element.textContent = secondaryHost ? `Secondary DNS · ${secondaryHost}` : "Secondary DNS · standby node"; });
  };

  form.querySelectorAll('[name="deployment_mode"]').forEach((input) => input.addEventListener("change", updateMode));
  ["virtual_ip", "prefix_length", "gateway_address", "primary_api_base_url", "secondary_api_base_url"].forEach((name) => field(name).addEventListener("input", updateTopology));

  form.querySelectorAll("[data-ha-test-node]").forEach((button) => {
    button.addEventListener("click", async () => {
      const node = button.dataset.haTestNode;
      const result = form.querySelector(`[data-ha-test-result="${node}"]`);
      const nodeField = (suffix) => field(`${node}_${suffix}`);
      if (!nodeField("name").reportValidity() || !nodeField("api_base_url").reportValidity()) return;
      const data = new FormData();
      data.set("csrf_token", field("csrf_token").value);
      data.set("provider_key", field("provider_key").value);
      data.set("node", node);
      data.set(`${node}_name`, nodeField("name").value);
      data.set(`${node}_api_base_url`, nodeField("api_base_url").value);
      data.set(`${node}_secret`, nodeField("secret").value);
      if (nodeField("ssl_verify").checked) data.set(`${node}_ssl_verify`, "1");
      const original = button.textContent;
      button.disabled = true;
      button.textContent = "Testing…";
      result.className = "muted";
      result.textContent = "Contacting Pi-hole with a read-only API request…";
      try {
        const response = await fetch("/high-availability/clusters/test-connection", { method: "POST", body: data, credentials: "same-origin" });
        const payload = await response.json();
        tested[node] = Boolean(response.ok && payload.ok);
        result.className = tested[node] ? "ha-test-result is-success" : "ha-test-result is-error";
        result.textContent = payload.message || "The connection test did not return a result.";
      } catch (_error) {
        tested[node] = false;
        result.className = "ha-test-result is-error";
        result.textContent = "Kaya could not complete the connection test. Check the URL and try again.";
      } finally {
        button.disabled = false;
        button.textContent = original;
        updateTopology();
      }
    });
  });

  updateMode();
});
