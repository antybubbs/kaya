document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("form.ha-wizard");
  if (!form) return;

  form.querySelectorAll("[data-ha-test-node]").forEach((button) => {
    button.addEventListener("click", async () => {
      const node = button.dataset.haTestNode;
      const result = form.querySelector(`[data-ha-test-result="${node}"]`);
      const field = (suffix) => form.elements.namedItem(`${node}_${suffix}`);
      if (!field("name").reportValidity() || !field("api_base_url").reportValidity()) return;
      const data = new FormData();
      data.set("csrf_token", form.elements.namedItem("csrf_token").value);
      data.set("provider_key", form.elements.namedItem("provider_key").value);
      data.set("node", node);
      data.set(`${node}_name`, field("name").value);
      data.set(`${node}_api_base_url`, field("api_base_url").value);
      data.set(`${node}_secret`, field("secret").value);
      if (field("ssl_verify").checked) data.set(`${node}_ssl_verify`, "1");
      const original = button.textContent;
      button.disabled = true;
      button.textContent = "Testing…";
      result.className = "muted";
      result.textContent = "Contacting Pi-hole using a read-only API request…";
      try {
        const response = await fetch("/high-availability/clusters/test-connection", { method: "POST", body: data, credentials: "same-origin" });
        const payload = await response.json();
        result.className = response.ok && payload.ok ? "ha-test-result is-success" : "ha-test-result is-error";
        result.textContent = payload.message || "The connection test did not return a result.";
      } catch (_error) {
        result.className = "ha-test-result is-error";
        result.textContent = "Kaya could not complete the connection test. Check the URL and try again.";
      } finally {
        button.disabled = false;
        button.textContent = original;
      }
    });
  });
});
