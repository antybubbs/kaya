(function () {
  "use strict";

  var fingerprintPattern = /SHA256:[A-Za-z0-9+/]{43}/g;

  function fingerprintFrom(value) {
    var matches = String(value || "").match(fingerprintPattern) || [];
    return matches.length === 1 ? matches[0] : "";
  }

  document.querySelectorAll("[data-ssh-identity-verify]").forEach(function (container) {
    var candidate = fingerprintFrom(container.dataset.candidateFingerprint);
    var input = container.querySelector("[data-server-fingerprint]");
    var status = container.querySelector("[data-fingerprint-match]");
    var form = container.closest("form");
    var button = (form || container).querySelector("[data-trust-button]");
    if (!candidate || !input || !status || !button) return;

    function compare() {
      var supplied = fingerprintFrom(input.value);
      var matches = supplied !== "" && supplied === candidate;
      button.disabled = !matches;
      status.classList.toggle("is-match", matches);
      status.classList.toggle("is-mismatch", supplied !== "" && !matches);
      status.textContent = supplied === ""
        ? "Waiting for the server-console fingerprint."
        : matches
          ? "Fingerprints match. Kaya will re-scan once more before saving trust."
          : "Fingerprints do not match. Do not trust this server identity.";
    }

    input.addEventListener("input", compare);
    compare();
  });
})();
