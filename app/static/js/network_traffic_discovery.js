(function () {
  const app = document.querySelector('[data-traffic-panel="discovery"]');
  if (!app || app.hidden) return;
  const root = document.querySelector('[data-traffic-app]');
  const csrf = root?.dataset.csrf || '';
  const canManage = root?.dataset.canManage === 'true';
  const pageSize = 50;
  let page = 1;
  let lastItems = [];
  let sourceNames = new Map();
  const esc = value => { const node = document.createElement('span'); node.textContent = value == null ? '' : String(value); return node.innerHTML; };
  const request = async (url, options = {}) => {
    const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.method ? { 'X-CSRF-Token': csrf } : {}) }, ...options });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.detail || 'The discovery request could not be completed.');
    return payload;
  };
  const statusLabel = { linked: 'Linked', unlinked: 'Unlinked', ignored: 'Ignored', stale: 'Stale', ambiguous: 'Ambiguous', unmatched: 'Unmatched' };
  const roleLabel = value => String(value || '').replaceAll('_', ' ');
  const itemKey = item => [item.source_id, item.exporter_identity, item.endpoint_role, item.endpoint_ip].join('|');
  const dateLabel = value => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : 'No data';
  const setMessage = (value, error = false) => { const node = app.querySelector('[data-discovery-status-message]'); if (node) { node.textContent = value || ''; node.classList.toggle('is-error', error); } };
  const actionButton = (item) => {
    if (!canManage) return '<span class="muted">Administrator action required</span>';
    const base = `/api/network-discovery/sources/${encodeURIComponent(item.source_id)}/endpoints/${encodeURIComponent(item.exporter_identity)}/${encodeURIComponent(item.endpoint_role)}/${encodeURIComponent(item.endpoint_ip)}`;
    if (item.status === 'linked') return `<button class="button secondary compact" type="button" data-discovery-action="unlink" data-discovery-key="${esc(itemKey(item))}" data-discovery-url="${esc(base + '/unlink')}">Unlink</button>`;
    if (item.status === 'ignored') return `<button class="button secondary compact" type="button" data-discovery-action="unignore" data-discovery-key="${esc(itemKey(item))}" data-discovery-url="${esc(base + '/unignore')}">Unignore</button>`;
    const translated = String(item.endpoint_role || '').startsWith('translated_');
    const link = !translated && item.managed_ip_address_id ? `<button class="button compact" type="button" data-discovery-action="link" data-discovery-id="${esc(item.managed_ip_address_id)}" data-discovery-url="${esc(base + '/link')}">Link candidate</button>` : '';
    const reason = translated ? '<small class="muted">Translated endpoint cannot be linked</small>' : '';
    const keyedLink = link.replace('data-discovery-action="link"', `data-discovery-key="${esc(itemKey(item))}" data-discovery-action="link"`);
    return `${keyedLink}${reason}<button class="button secondary compact" type="button" data-discovery-action="ignore" data-discovery-key="${esc(itemKey(item))}" data-discovery-url="${esc(base + '/ignore')}">Ignore</button>`;
  };
  const renderRows = () => {
    const target = app.querySelector('[data-discovery-rows]');
    const query = (app.querySelector('[data-discovery-search]')?.value || '').trim().toLowerCase();
    const items = lastItems.filter(item => !query || `${item.endpoint_ip} ${item.exporter_identity}`.toLowerCase().includes(query));
    app.querySelector('[data-discovery-empty]').hidden = items.length > 0;
    target.innerHTML = items.length ? items.map(item => `<tr><th scope="row"><span class="mono">${esc(item.endpoint_ip)}</span><small class="muted">${esc(item.confidence || 'unknown')} confidence</small></th><td><strong>${esc(sourceNames.get(String(item.source_id)) || `Source ${item.source_id}`)}</strong><small class="muted mono">${esc(item.exporter_identity)}</small></td><td>${esc(roleLabel(item.endpoint_role))}</td><td>${esc(item.classification || 'unknown')}</td><td><span>${esc(item.observation_count)}</span><small class="muted">${esc(dateLabel(item.last_seen_at))}</small></td><td><span class="traffic-status traffic-status-${esc(item.status)}">${esc(statusLabel[item.status] || item.status)}</span><small class="muted">${esc(item.status_reason || '')}</small></td><td><div class="discovery-actions">${actionButton(item)}</div></td></tr>`).join('') : '<tr><td colspan="7" class="muted">No matching discovery observations.</td></tr>';
    target.querySelectorAll('[data-discovery-action]').forEach(button => button.addEventListener('click', () => decide(button, items.find(item => itemKey(item) === button.dataset.discoveryKey) || null)));
  };
  const loadSummary = async () => {
    const payload = await request('/api/network-discovery/summary');
    Object.entries({ total: payload.total, ...(payload.counts || {}) }).forEach(([key, value]) => { const node = app.querySelector(`[data-discovery-count="${key}"]`); if (node) node.textContent = String(value ?? 0); });
  };
  const loadSources = async () => {
    const payload = await request('/api/network-discovery/capabilities');
    const select = app.querySelector('[data-discovery-source]');
    sourceNames = new Map((payload.sources || []).map(source => [String(source.id), source.name]));
    if (select) select.innerHTML = '<option value="">All supported sources</option>' + (payload.sources || []).filter(source => source.supports_discovery).map(source => `<option value="${esc(source.id)}">${esc(source.name)}</option>`).join('');
    const state = app.querySelector('[data-discovery-state]');
    if (state) { state.textContent = payload.discovery_enabled ? 'Enabled' : 'Disabled'; state.className = `traffic-status traffic-status-${payload.discovery_enabled ? 'healthy' : 'disabled'}`; }
    const moduleState = document.querySelector('[data-traffic-module-state]');
    if (moduleState) moduleState.textContent = payload.discovery_enabled ? 'Discovery enabled' : 'Discovery disabled';
  };
  const loadRows = async () => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    const source = app.querySelector('[data-discovery-source]')?.value; const status = app.querySelector('[data-discovery-status]')?.value;
    if (source) params.set('source_id', source); if (status) params.set('status', status);
    const payload = await request(`/api/network-discovery/observations?${params}`); lastItems = payload.items || [];
    app.querySelector('[data-discovery-page-label]').textContent = `Page ${page} · ${payload.total} result${payload.total === 1 ? '' : 's'}`;
    app.querySelector('[data-discovery-prev]').disabled = page <= 1; app.querySelector('[data-discovery-next]').disabled = page * pageSize >= payload.total;
    renderRows();
  };
  const decide = async (button, item) => {
    if (!item || !window.confirm(`${button.dataset.discoveryAction === 'link' ? 'Link' : button.dataset.discoveryAction === 'ignore' ? 'Ignore' : button.dataset.discoveryAction === 'unignore' ? 'Unignore' : 'Unlink'} this discovered endpoint?`)) return;
    button.disabled = true;
    try { await request(button.dataset.discoveryUrl, { method: 'POST', body: JSON.stringify({ confirmation: true, managed_ip_address_id: button.dataset.discoveryId ? Number(button.dataset.discoveryId) : null, reason: button.dataset.discoveryAction === 'ignore' ? 'ignored_by_administrator' : null }) }); setMessage('Discovery decision saved.'); await Promise.all([loadSummary(), loadRows()]); } catch (error) { setMessage(error.message, true); button.disabled = false; }
  };
  app.querySelector('[data-discovery-filters]')?.addEventListener('submit', event => { event.preventDefault(); page = 1; Promise.all([loadSummary(), loadRows()]).catch(error => setMessage(error.message, true)); });
  app.querySelector('[data-discovery-search]')?.addEventListener('input', renderRows);
  app.querySelector('[data-discovery-refresh]')?.addEventListener('click', () => Promise.all([loadSources(), loadSummary(), loadRows()]).catch(error => setMessage(error.message, true)));
  app.querySelector('[data-discovery-prev]')?.addEventListener('click', () => { if (page > 1) { page -= 1; loadRows().catch(error => setMessage(error.message, true)); } });
  app.querySelector('[data-discovery-next]')?.addEventListener('click', () => { page += 1; loadRows().catch(error => setMessage(error.message, true)); });
  Promise.all([loadSources(), loadSummary(), loadRows()]).catch(error => setMessage(error.message, true));
})();
