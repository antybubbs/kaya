(function () {
  const root = (document.body.dataset.appRoot || "").replace(/\/$/, "");
  const updateToast = document.querySelector("[data-pwa-update]");
  const refreshButton = document.querySelector("[data-pwa-refresh]");
  const installButton = document.querySelector("[data-install-kaya]");
  const iosInstallGuide = document.querySelector("[data-ios-install-guide]");
  const connectionBanner = document.querySelector("[data-connection-banner]");
  let installPrompt = null;
  let refreshing = false;
  let restoreTimer = null;

  function standalone() {
    return window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true;
  }

  function iosDevice() {
    return /iPad|iPhone|iPod/i.test(navigator.userAgent) ||
      (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  }

  function setConnectionState() {
    if (!connectionBanner) return;
    window.clearTimeout(restoreTimer);
    if (!navigator.onLine) {
      connectionBanner.textContent = "Offline — live data is temporarily unavailable.";
      connectionBanner.classList.add("is-offline");
      connectionBanner.hidden = false;
    } else if (connectionBanner.classList.contains("is-offline")) {
      connectionBanner.textContent = "Connection restored.";
      connectionBanner.classList.remove("is-offline");
      connectionBanner.hidden = false;
      restoreTimer = window.setTimeout(() => { connectionBanner.hidden = true; }, 3500);
    } else {
      connectionBanner.hidden = true;
    }
    window.dispatchEvent(new CustomEvent("kaya:connection", { detail: { online: navigator.onLine } }));
  }

  window.addEventListener("online", setConnectionState);
  window.addEventListener("offline", setConnectionState);
  setConnectionState();

  window.addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    installPrompt = event;
    if (installButton && !standalone()) installButton.hidden = false;
  });

  installButton?.addEventListener("click", async () => {
    if (installPrompt) {
      installButton.hidden = true;
      await installPrompt.prompt();
      await installPrompt.userChoice;
      installPrompt = null;
      return;
    }
    if (iosDevice() && iosInstallGuide) {
      if (typeof iosInstallGuide.showModal === "function") iosInstallGuide.showModal();
      else iosInstallGuide.setAttribute("open", "");
    }
  });

  window.addEventListener("appinstalled", () => {
    installPrompt = null;
    if (installButton) installButton.hidden = true;
  });

  if (installButton && iosDevice() && !standalone()) installButton.hidden = false;

  if (!("serviceWorker" in navigator) || !window.isSecureContext) return;

  function showUpdate(worker) {
    if (!worker || !updateToast) return;
    updateToast.hidden = false;
    refreshButton?.addEventListener("click", () => {
      refreshing = true;
      worker.postMessage({ type: "SKIP_WAITING" });
    }, { once: true });
  }

  navigator.serviceWorker.addEventListener("controllerchange", () => {
    if (refreshing) window.location.reload();
  });

  window.addEventListener("load", async () => {
    try {
      const registration = await navigator.serviceWorker.register(`${root}/service-worker.js`, { scope: `${root || ""}/` });
      if (registration.waiting) showUpdate(registration.waiting);
      registration.addEventListener("updatefound", () => {
        const worker = registration.installing;
        worker?.addEventListener("statechange", () => {
          if (worker.state === "installed" && navigator.serviceWorker.controller) showUpdate(worker);
        });
      });
    } catch (_error) {
      // PWA support is optional; normal browser operation remains available.
    }
  });
})();
