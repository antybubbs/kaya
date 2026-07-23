(() => {
  const form = document.querySelector("[data-authentication-policy-form]");
  if (!form) return;

  const mode = form.querySelector("[data-authentication-mode]");
  const description = form.querySelector("[data-authentication-mode-description]");
  const preferredOption = form.querySelector("[data-preferred-local-option]");
  const preferredCheckbox = preferredOption?.querySelector("input");
  const oidcOnlyOptions = Array.from(form.querySelectorAll("[data-oidc-only-option]"));
  const descriptions = {
    local_only: "Users sign in using their Kaya email address and password.",
    local_and_oidc: "Users may sign in using either Kaya credentials or the configured identity provider.",
    oidc_preferred: "Single sign-on is presented as the primary option. Local sign-in may optionally remain visible.",
    oidc_required: "Standard email/password sign-in is disabled. Emergency local access remains available separately for break-glass administrators.",
  };

  const update = () => {
    const selected = mode?.value || "local_only";
    if (description) description.textContent = descriptions[selected] || descriptions.local_only;
    if (preferredOption) preferredOption.hidden = selected !== "oidc_preferred";
    if (preferredCheckbox) preferredCheckbox.disabled = selected !== "oidc_preferred";
    oidcOnlyOptions.forEach((element) => { element.hidden = selected !== "oidc_required"; });
  };

  mode?.addEventListener("change", update);
  update();

  form.querySelector("[data-copy-emergency-url]")?.addEventListener("click", async (event) => {
    const input = form.querySelector("[data-emergency-url]");
    if (!input) return;
    try {
      await navigator.clipboard.writeText(input.value);
      event.currentTarget.textContent = "Copied";
    } catch {
      input.select();
      document.execCommand("copy");
    }
  });
})();
