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
    window.setTimeout(() => {
      if (button) {
        button.disabled = false;
        button.textContent = "Try linking again";
      }
      if (status) status.textContent = " The provider is taking too long to respond. Check the Kaya audit log and provider connectivity.";
    }, 35000);
  });
});
