(() => {
  const wizard = document.querySelector('[data-secure-send-wizard]');
  if (wizard) {
    const steps = [...wizard.querySelectorAll('[data-wizard-step]')];
    const progress = [...wizard.querySelectorAll('.wizard-progress li')];
    const back = wizard.querySelector('[data-wizard-back]');
    const next = wizard.querySelector('[data-wizard-next]');
    const submit = wizard.querySelector('[data-wizard-submit]');
    let current = 0;
    const show = index => { current = index; steps.forEach((step, i) => { step.hidden = i !== index; step.classList.toggle('active', i === index); }); progress.forEach((item, i) => item.classList.toggle('active', i <= index)); back.hidden = index === 0; next.hidden = index === steps.length - 1; submit.hidden = index !== steps.length - 1; };
    next.addEventListener('click', () => { const fields = [...steps[current].querySelectorAll('input[required],select[required],textarea[required]')].filter(field => !field.closest('[hidden]')); if (fields.every(field => field.reportValidity())) show(Math.min(current + 1, steps.length - 1)); });
    back.addEventListener('click', () => show(Math.max(0, current - 1)));
    const updateRecipient = () => { const type = wizard.querySelector('[name=recipient_type]:checked').value; const external = wizard.querySelector('[data-external-recipient]'); const internal = wizard.querySelector('[data-internal-recipient]'); external.hidden = type !== 'external'; internal.hidden = type !== 'internal'; const vault = wizard.querySelector('[data-vault-option]'); if (vault) vault.hidden = type !== 'internal'; const value = type === 'internal' ? internal.querySelector('option:checked')?.textContent : wizard.querySelector('[name=recipient_email]').value; wizard.querySelector('[data-review-recipient]').textContent = value || 'Not selected'; };
    wizard.querySelectorAll('[name=recipient_type],[name=recipient_email],[name=internal_recipient_id]').forEach(field => field.addEventListener('change', updateRecipient)); wizard.querySelector('[name=recipient_email]').addEventListener('input', updateRecipient);
    const expiry = wizard.querySelector('[name=expiry]'); expiry.addEventListener('change', () => { wizard.querySelector('[data-custom-expiry]').hidden = expiry.value !== 'custom'; wizard.querySelector('[data-review-expiry]').textContent = expiry.options[expiry.selectedIndex].text; });
    const files = wizard.querySelector('[name=files]'); if (files) files.addEventListener('change', () => { const note = wizard.querySelector('[name=secure_note]')?.value.trim(); wizard.querySelector('[data-review-content]').textContent = `${files.files.length} file${files.files.length === 1 ? '' : 's'}${note ? ' and secure note' : ''}`; });
    updateRecipient(); show(0);
  }
  document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => { const input = button.parentElement.querySelector('[data-copy-value]'); await navigator.clipboard.writeText(input.value); button.textContent = 'Copied'; setTimeout(() => { button.textContent = 'Copy'; }, 1500); }));
  const gatewayStatus = document.querySelector('[data-gateway-status]');
  if (gatewayStatus) {
    const root = (document.body.dataset.appRoot || '').replace(/\/$/, '');
    const label = gatewayStatus.querySelector('[data-gateway-label]');
    const detail = gatewayStatus.querySelector('[data-gateway-detail]');
    let checking = false;
    const renderGateway = data => {
      const state = data.state === 'running' ? 'running' : 'unavailable';
      gatewayStatus.classList.remove('gateway-running', 'gateway-unavailable', 'gateway-checking');
      gatewayStatus.classList.add(`gateway-${state}`);
      label.textContent = data.label || (state === 'running' ? 'Gateway running' : 'Gateway unavailable');
      detail.textContent = data.detail || 'Live status check failed.';
      gatewayStatus.title = data.checked_at ? `Last checked ${data.checked_at}` : 'Live gateway status';
    };
    const checkGateway = async () => {
      if (checking || document.hidden) return;
      checking = true;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);
      try {
        const response = await fetch(`${root}/security/secure-send/gateway-status`, {cache: 'no-store', credentials: 'same-origin', headers: {'Accept': 'application/json'}, signal: controller.signal});
        if (!response.ok) throw new Error('status unavailable');
        renderGateway(await response.json());
      } catch (_error) {
        renderGateway({state: 'unavailable', label: 'Gateway unavailable', detail: 'Live status check failed. Check the secure-send-gateway container.'});
      } finally {
        clearTimeout(timeout);
        checking = false;
      }
    };
    checkGateway();
    setInterval(checkGateway, 3000);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) checkGateway(); });
  }
})();
