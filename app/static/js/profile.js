document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("[data-oidc-link-form]");
  if (!form) return;
  form.addEventListener("submit", () => {
    const button = form.querySelector('button[type="submit"]');
    const status = form.querySelector("[data-oidc-link-status]");
    if (button) {
      button.disabled = true;
      button.textContent = "Redirecting…";
    }
    if (status) status.textContent = " Connecting to your identity provider.";
  });
});
