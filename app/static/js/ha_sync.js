(() => {
  const form = document.querySelector("[data-ha-sync-confirmation]");
  if (!form) return;
  const checks = Array.from(form.querySelectorAll('input[type="checkbox"]'));
  const submit = form.querySelector('button[type="submit"]');
  if (!submit) return;
  const blocked = form.dataset.syncBlocked === "1";
  const update = () => { submit.disabled = blocked || !checks.every((check) => check.checked); };
  checks.forEach((check) => check.addEventListener("change", update));
  update();
})();
