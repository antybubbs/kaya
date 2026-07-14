document.addEventListener("submit", (event) => {
  const form = event.target.closest("form[data-confirm-delete]");
  if (!form) return;
  const message = form.dataset.confirmDelete || "Permanently delete this record? This cannot be undone.";
  if (!window.confirm(message)) event.preventDefault();
});
