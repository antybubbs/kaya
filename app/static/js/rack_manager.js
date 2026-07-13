document.addEventListener('DOMContentLoaded', () => {
  const form = document.querySelector('[data-rack-device-form]');
  const rails = document.querySelector('.rack-rails[data-rack-id]');
  const deleteForm = document.querySelector('[data-rack-delete-form]');

  deleteForm?.addEventListener('submit', (event) => {
    const rackName = deleteForm.dataset.rackName || 'this rack';
    const itemCount = Number.parseInt(deleteForm.dataset.rackItemCount || '0', 10);
    const placements = `${itemCount} device placement${itemCount === 1 ? '' : 's'}`;
    const confirmed = window.confirm(`Delete rack "${rackName}"? This permanently removes the rack and ${placements}. Linked hardware assets will remain.`);
    if (!confirmed) event.preventDefault();
  });

  if (form) {
    const assetSelect = form.querySelector('[data-asset-select]');
    const nameInput = form.querySelector('[data-device-name]');
    const categoryInput = form.querySelector('[data-device-category]');
    const startInput = form.querySelector('[data-start-u]');

    assetSelect?.addEventListener('change', () => {
      const option = assetSelect.selectedOptions[0];
      if (!option || option.value === '0') return;
      if (nameInput) nameInput.value = option.dataset.name || '';
      if (categoryInput) categoryInput.value = option.dataset.category || '';
    });

    document.querySelectorAll('[data-rack-u]').forEach((button) => {
      button.addEventListener('click', () => {
        if (!startInput) return;
        startInput.value = button.dataset.rackU || startInput.value;
        startInput.focus();
        startInput.select();
      });
    });
  }

  if (!rails) return;

  const rackId = rails.dataset.rackId;
  const rackHeight = Number.parseInt(rails.dataset.rackHeight || '0', 10);
  const csrfToken = rails.dataset.csrfToken || '';
  const units = Array.from(rails.querySelectorAll('.rack-unit[data-rack-u]'));
  const devices = Array.from(rails.querySelectorAll('.rack-device[data-item-id]'));

  if (!rackId || !rackHeight || !csrfToken || !units.length || !devices.length) return;

  const clamp = (value, min, max) => Math.min(Math.max(value, min), max);
  const getUnitStepPx = () => {
    const first = units[0];
    if (!first) return 20;
    const rect = first.getBoundingClientRect();
    const styles = window.getComputedStyle(rails);
    const gap = Number.parseFloat(styles.rowGap || styles.gap || '2') || 2;
    return Math.max(12, rect.height + gap);
  };

  const applyDeviceLayout = (item, startU, heightU) => {
    const rowStart = rackHeight - startU - heightU + 2;
    item.style.gridRow = `${rowStart} / span ${heightU}`;
    item.dataset.startU = String(startU);
    item.dataset.heightU = String(heightU);
    item.classList.toggle('rack-device-1u', heightU === 1);
    item.classList.toggle('rack-device-2u', heightU === 2);
    const endU = startU + heightU - 1;
    item.title = `U${startU}${heightU > 1 ? `-U${endU}` : ''}`;
    const meta = item.querySelector('small');
    if (meta) {
      meta.textContent = meta.textContent.replace(/ - \d+U$/, ` - ${heightU}U`);
    }
  };

  const saveDeviceLayout = async (item, startU, heightU) => {
    const itemId = item.dataset.itemId;
    if (!itemId) return;
    const payload = new URLSearchParams();
    payload.set('csrf_token', csrfToken);
    payload.set('start_u', String(startU));
    payload.set('height_u', String(heightU));

    const response = await fetch(`/infrastructure/rack-manager/${rackId}/items/${itemId}/layout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: payload.toString(),
    });

    let data = {};
    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok || !data.ok) {
      throw new Error(data.detail || 'Unable to update rack layout.');
    }
    applyDeviceLayout(item, data.start_u, data.height_u);
  };

  const clearDropTargets = () => {
    units.forEach((unit) => unit.classList.remove('drop-target'));
  };

  let interaction = null;

  const finishInteraction = async () => {
    if (!interaction) return;
    const current = interaction;
    interaction = null;
    clearDropTargets();
    current.item.classList.remove('is-dragging');

    if (current.previewStart === current.startU && current.previewHeight === current.heightU) {
      applyDeviceLayout(current.item, current.startU, current.heightU);
      return;
    }

    try {
      await saveDeviceLayout(current.item, current.previewStart, current.previewHeight);
    } catch (error) {
      applyDeviceLayout(current.item, current.startU, current.heightU);
      window.alert(error.message || 'Unable to move this device there.');
    }
  };

  const onPointerMove = (event) => {
    if (!interaction) return;
    event.preventDefault();

    if (interaction.mode === 'move') {
      const target = document.elementFromPoint(event.clientX, event.clientY)?.closest('.rack-unit[data-rack-u]');
      if (!target) {
        clearDropTargets();
        return;
      }
      clearDropTargets();
      target.classList.add('drop-target');
      const hoveredU = Number.parseInt(target.dataset.rackU || '0', 10);
      const maxStart = Math.max(1, rackHeight - interaction.heightU + 1);
      const nextStart = clamp(hoveredU, 1, maxStart);
      if (nextStart !== interaction.previewStart) {
        interaction.previewStart = nextStart;
        applyDeviceLayout(interaction.item, interaction.previewStart, interaction.previewHeight);
      }
      return;
    }

    if (interaction.mode === 'resize') {
      const deltaUnits = Math.round((interaction.startY - event.clientY) / interaction.unitStepPx);
      const maxHeight = Math.max(1, rackHeight - interaction.startU + 1);
      const nextHeight = clamp(interaction.heightU + deltaUnits, 1, maxHeight);
      if (nextHeight !== interaction.previewHeight) {
        interaction.previewHeight = nextHeight;
        applyDeviceLayout(interaction.item, interaction.previewStart, interaction.previewHeight);
      }
    }
  };

  const removeInteractionListeners = () => {
    window.removeEventListener('pointermove', onPointerMove);
    window.removeEventListener('pointerup', onPointerUp);
    window.removeEventListener('pointercancel', onPointerCancel);
    window.removeEventListener('blur', onWindowBlur);
    document.removeEventListener('visibilitychange', onVisibilityChange);
  };

  const onPointerUp = () => {
    removeInteractionListeners();
    void finishInteraction();
  };

  const onPointerCancel = () => {
    removeInteractionListeners();
    void finishInteraction();
  };

  const onWindowBlur = () => {
    removeInteractionListeners();
    void finishInteraction();
  };

  const onVisibilityChange = () => {
    if (document.visibilityState !== 'hidden') return;
    removeInteractionListeners();
    void finishInteraction();
  };

  const addInteractionListeners = () => {
    window.addEventListener('pointermove', onPointerMove);
    window.addEventListener('pointerup', onPointerUp, { once: true });
    window.addEventListener('pointercancel', onPointerCancel, { once: true });
    window.addEventListener('blur', onWindowBlur, { once: true });
    document.addEventListener('visibilitychange', onVisibilityChange, { once: true });
  };

  devices.forEach((item) => {
    const resizeHandle = item.querySelector('.rack-device-resize');

    item.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      if (event.target.closest('.rack-device-resize')) return;
      clearDropTargets();
      const startU = Number.parseInt(item.dataset.startU || '1', 10);
      const heightU = Number.parseInt(item.dataset.heightU || '1', 10);
      interaction = {
        mode: 'move',
        item,
        startU,
        heightU,
        previewStart: startU,
        previewHeight: heightU,
      };
      item.classList.add('is-dragging');
      addInteractionListeners();
    });

    resizeHandle?.addEventListener('pointerdown', (event) => {
      if (event.button !== 0) return;
      event.preventDefault();
      event.stopPropagation();
      clearDropTargets();
      const startU = Number.parseInt(item.dataset.startU || '1', 10);
      const heightU = Number.parseInt(item.dataset.heightU || '1', 10);
      interaction = {
        mode: 'resize',
        item,
        startU,
        heightU,
        previewStart: startU,
        previewHeight: heightU,
        startY: event.clientY,
        unitStepPx: getUnitStepPx(),
      };
      item.classList.add('is-dragging');
      addInteractionListeners();
    });
  });
});
