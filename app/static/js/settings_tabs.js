(() => {
  const root = document.querySelector("[data-settings-tabs]");
  if (!root) return;

  const tabs = Array.from(root.querySelectorAll("[data-settings-tab]"));
  const panels = Array.from(root.querySelectorAll("[data-settings-panel]"));
  const storageKey = root.dataset.settingsStorageKey || "kaya.siteAdministration.activeTab";

  const readStoredTab = () => {
    try {
      return window.localStorage.getItem(storageKey);
    } catch {
      return "";
    }
  };

  const writeStoredTab = (name) => {
    try {
      window.localStorage.setItem(storageKey, name);
    } catch {
      // Tab switching should still work when browser storage is unavailable.
    }
  };

  const activate = (name) => {
    const fallback = tabs[0]?.dataset.settingsTab || "";
    const activeName = panels.some((panel) => panel.dataset.settingsPanel === name) ? name : fallback;

    tabs.forEach((tab) => {
      const active = tab.dataset.settingsTab === activeName;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });

    panels.forEach((panel) => {
      const active = panel.dataset.settingsPanel === activeName;
      panel.hidden = !active;
      panel.classList.toggle("active", active);
    });

    if (activeName) {
      writeStoredTab(activeName);
    }
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => activate(tab.dataset.settingsTab));
  });

  const publicIpButton = root.querySelector("[data-public-ip-check]");
  const publicIpResult = root.querySelector("[data-public-ip-result]");
  const publicIpDetail = root.querySelector("[data-public-ip-detail]");
  if (publicIpButton && publicIpResult && publicIpDetail) {
    publicIpButton.addEventListener("click", async () => {
      publicIpButton.disabled = true;
      publicIpResult.textContent = "Checking...";
      publicIpDetail.textContent = "Kaya is asking an external IP service from the server.";
      try {
        const response = await fetch("/system/site-administration/security/public-ip", {
          headers: { Accept: "application/json" },
        });
        const data = await response.json();
        if (!response.ok || !data.ok) {
          throw new Error(data.error || "Public IP check failed");
        }
        publicIpResult.textContent = data.ip;
        publicIpDetail.textContent = `Reported by ${data.source}. This is Kaya's outbound public IP.`;
      } catch (error) {
        publicIpResult.textContent = "Unavailable";
        publicIpDetail.textContent = error.message || "Kaya could not reach a public IP service.";
      } finally {
        publicIpButton.disabled = false;
      }
    });
  }

  const inboundButton = root.querySelector("[data-inbound-check]");
  const inboundResult = root.querySelector("[data-inbound-result]");
  const inboundDetail = root.querySelector("[data-inbound-detail]");
  if (inboundButton && inboundResult && inboundDetail) {
    inboundButton.addEventListener("click", async () => {
      inboundButton.disabled = true;
      inboundResult.textContent = "Checking...";
      inboundDetail.textContent = "Kaya is resolving the hostname used by this browser request.";
      try {
        const response = await fetch("/system/site-administration/security/inbound", {
          headers: { Accept: "application/json" },
        });
        const data = await response.json();
        if (!response.ok || !data.ok) {
          throw new Error(data.error || "Inbound DNS check failed");
        }
        inboundResult.textContent = data.addresses.join(", ");
        inboundDetail.textContent = `Resolved ${data.host}. This is where browsers are routed before reaching Kaya.`;
      } catch (error) {
        inboundResult.textContent = "Unavailable";
        inboundDetail.textContent = error.message || "Kaya could not resolve the inbound hostname.";
      } finally {
        inboundButton.disabled = false;
      }
    });
  }

  activate(readStoredTab() || tabs[0]?.dataset.settingsTab || "");
})();
