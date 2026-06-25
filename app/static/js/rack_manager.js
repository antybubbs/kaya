document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('[data-rack-device-form]');
  if (!form) return;

  const assetSelect = form.querySelector('[data-asset-select]');
  const nameInput = form.querySelector('[data-device-name]');
  const categoryInput = form.querySelector('[data-device-category]');
  const startInput = form.querySelector('[data-start-u]');

  assetSelect?.addEventListener('change', () => {
    const option = assetSelect.selectedOptions[0];
    if (!option || option.value === '0') return;
    if (nameInput && !nameInput.value.trim()) nameInput.value = option.dataset.name || '';
    if (categoryInput && !categoryInput.value.trim()) categoryInput.value = option.dataset.category || '';
  });

  document.querySelectorAll('[data-rack-u]').forEach((button) => {
    button.addEventListener('click', () => {
      if (!startInput) return;
      startInput.value = button.dataset.rackU || startInput.value;
      startInput.focus();
      startInput.select();
    });
  });
});