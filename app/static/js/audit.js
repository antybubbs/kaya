document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-audit-confirm]").forEach(input => {
    const button = input.closest("form")?.querySelector("button.danger");
    const sync = () => { if (button) button.disabled = input.value !== input.dataset.auditConfirm; };
    input.addEventListener("input", sync); sync();
  });
  const preview = document.querySelector("[data-audit-purge-preview]");
  const result = document.querySelector("[data-audit-purge-preview-result]");
  preview?.addEventListener("submit", async event => {
    event.preventDefault();
    result.textContent = "Checking…";
    try {
      const response = await fetch(preview.action, {method: "POST", body: new FormData(preview), credentials: "same-origin"});
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Preview failed.");
      result.textContent = `${data.count} matching event(s).`;
    } catch (error) { result.textContent = error.message; }
  });
});
