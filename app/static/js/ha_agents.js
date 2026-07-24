(() => {
  const rootPath = String(document.body.dataset.appRoot || "").replace(/\/+$/, "");
  const browserBaseUrl = `${window.location.origin}${rootPath}`;

  document.querySelectorAll("[data-ha-command]").forEach((command) => {
    const generatedOrigin = command.closest("[data-ha-command-origin]")?.dataset.haCommandOrigin?.replace(/\/+$/, "");
    if (!generatedOrigin || !/^https?:\/\//i.test(generatedOrigin)) return;
    command.textContent = command.textContent.split(generatedOrigin).join(browserBaseUrl);
  });

  document.querySelectorAll("[data-copy-ha-command]").forEach((button) => button.addEventListener("click", async () => {
    const command = button.closest(".ha-install-command")?.querySelector("[data-ha-command]");
    if (!command) return;
    const value = command.textContent.trim();
    try {
      await navigator.clipboard.writeText(value);
    } catch (_) {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(command);
      selection.removeAllRanges();
      selection.addRange(range);
      document.execCommand("copy");
      selection.removeAllRanges();
    }
    button.textContent = "Copied";
    const label = button.textContent;
    window.setTimeout(() => { button.textContent = label; }, 1500);
  }));
})();
