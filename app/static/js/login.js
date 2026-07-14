(function () {
  "use strict";

  document.querySelectorAll("[data-password-toggle]").forEach(function (button) {
    var input = document.getElementById(button.getAttribute("aria-controls"));
    if (!input) return;

    button.addEventListener("click", function () {
      var reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      button.setAttribute("aria-pressed", String(reveal));
      button.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
      input.focus({ preventScroll: true });
    });
  });

  document.querySelectorAll("[data-login-form]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (form.dataset.submitting === "true") {
        event.preventDefault();
        return;
      }
      form.dataset.submitting = "true";
      form.setAttribute("aria-busy", "true");

      var button = form.querySelector("[data-submit-button]");
      if (!button) return;
      button.disabled = true;
      button.textContent = button.dataset.loadingLabel || "Signing in…";
    });
  });
})();
