(() => {
  const button = document.querySelector("[data-copy-ha-install]");
  const command = document.querySelector("[data-ha-install-command]");
  if (!button || !command) return;
  button.addEventListener("click", async () => {
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
    window.setTimeout(() => { button.textContent = "Copy command"; }, 1500);
  });
})();
