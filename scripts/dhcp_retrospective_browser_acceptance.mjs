import fs from 'node:fs/promises';
import { chromium } from 'playwright';

// Authenticated acceptance for authorising retrospective DHCP closures in Data
// Integrity. Requires a disposable Kaya seeded by stage2b_acceptance_seed.py and
// dhcp_retrospective_acceptance_seed.py; FIXTURE_FILE is the latter's output.
const base = process.env.BASE_URL || 'http://127.0.0.1:18089';
const artifacts = process.env.ARTIFACT_DIR;
const password = process.env.ACCEPTANCE_PASSWORD || 'Stage2B-fixture-password-012345';
if (!artifacts || !process.env.FIXTURE_FILE) throw new Error('ARTIFACT_DIR and FIXTURE_FILE are required');
const fixture = JSON.parse(await fs.readFile(process.env.FIXTURE_FILE, 'utf8'));
await fs.mkdir(artifacts, { recursive: true });
const page_path = '/data/data-integrity';
const api = '/api/data-integrity';
const legacy = fixture.findings.legacy;
const expired = fixture.findings.expired;
const hostname = fixture.findings.hostname;
// Responses the test provokes on purpose (validation and CSRF failures).
const expected = { http: 0, console: 0 };
const expect400 = () => { expected.http += 1; expected.console += 1; };

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const evidence = { httpErrors: [], consoleErrors: [], pageErrors: [], cspViolations: [], screenshots: [], viewports: [], checks: [] };
const check = (condition, label) => { if (!condition) throw new Error(`check failed: ${label}`); evidence.checks.push(label); };

function watch(page, allowed = () => false) {
  page.on('response', response => {
    const path = new URL(response.url()).pathname;
    if (response.status() === 400 && expected.http > 0) { expected.http -= 1; return; }
    if (response.status() >= 400 && response.url().startsWith(base) && path !== '/favicon.ico' && !allowed(path, response.status())) evidence.httpErrors.push({ status: response.status(), path });
  });
  page.on('console', message => {
    if (message.type() !== 'error' || /status of 403/i.test(message.text())) return;
    if (/status of 400/i.test(message.text()) && expected.console > 0) { expected.console -= 1; return; }
    const source = message.location().url || '';
    if (/status of 404/i.test(message.text()) && new URL(source || base).pathname === '/favicon.ico') return;  // not served in tests
    evidence.consoleErrors.push(`${message.text()} (${source})`);
    if (/content security policy|csp/i.test(message.text())) evidence.cspViolations.push(message.text());
  });
  page.on('pageerror', error => evidence.pageErrors.push(String(error)));
}

async function login(page, email) {
  await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForLoadState('networkidle');
}

async function inspect(page, label) {
  const layout = await page.evaluate(() => ({ width: innerWidth, height: innerHeight, scrollWidth: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth }));
  if (layout.scrollWidth > layout.width + 1 || layout.bodyWidth > layout.width + 1) throw new Error(`${label}: horizontal overflow ${JSON.stringify(layout)}`);
  evidence.viewports.push({ label, ...layout });
}

async function shot(page, name) {
  await page.screenshot({ path: `${artifacts}/${name}.png`, fullPage: true });
  evidence.screenshots.push(`${name}.png`);
}

const finding = async (page, id) => page.evaluate(async ([url]) => (await fetch(url, { headers: { Accept: 'application/json' } })).json(), [`${api}/findings/${id}`]);

async function openFindings(page) {
  await page.goto(`${base}${page_path}?q=${encodeURIComponent('retrospective review')}&status=active`, { waitUntil: 'networkidle' });
}

async function investigate(page, id) {
  const button = page.locator(`[data-di-investigate="${id}"]`);
  if (await button.getAttribute('aria-expanded') !== 'true') await button.click();
  const panel = page.locator(`#di-panel-${id}`);
  await panel.getByRole('button', { name: 'Preview fix' }).waitFor({ state: 'visible' });
  return panel;
}

async function collapse(page, id) {
  const button = page.locator(`[data-di-investigate="${id}"]`);
  if (await button.getAttribute('aria-expanded') === 'true') await button.click();
}

try {
  // ------------------------------------------------ administrator with repair permission
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await context.newPage();
  watch(page);
  await login(page, 'stage2b-admin@example.invalid');
  await openFindings(page);
  for (const item of [legacy, expired]) check(await page.locator(`[data-di-investigate="${item.finding_id}"]`).count() === 1, `finding ${item.finding_id} listed under retrospective review`);
  await inspect(page, '1280x800 findings');
  await shot(page, 'retro-1280x800-findings');

  const panel = await investigate(page, legacy.finding_id);
  const text = await panel.innerText();
  for (const value of [fixture.macs.legacy, fixture.addresses.legacy, 'inferred_adoption', 'Retrospective review', 'Waits for administrator review', legacy.asset_tag, 'lease_ended']) check(text.includes(value), `legacy evidence shows ${value}`);
  await panel.getByRole('button', { name: 'Preview fix' }).click();
  await panel.getByText('Assignments that will be closed').waitFor();
  const apply = panel.getByRole('button', { name: 'Apply fix' });
  check(await apply.isDisabled(), 'apply is disabled until the review is confirmed');
  await inspect(page, '1280x800 preview');
  await shot(page, 'retro-1280x800-preview');

  // Cancellation: abandon the preview; nothing may change.
  await collapse(page, legacy.finding_id);
  let state = await finding(page, legacy.finding_id);
  check(state.status !== 'resolved' && state.live.detected, 'cancelled preview leaves the finding open and the assignment unchanged');

  // Responsive review at phone width, including the detail panel and bulk dialog.
  await page.setViewportSize({ width: 390, height: 844 });
  await openFindings(page);
  await inspect(page, '390x844 findings');
  const mobilePanel = await investigate(page, legacy.finding_id);
  await mobilePanel.getByRole('button', { name: 'Preview fix' }).click();
  await mobilePanel.getByText('Assignments that will be closed').waitFor();
  await inspect(page, '390x844 preview');
  await shot(page, 'retro-390x844-preview');
  await collapse(page, legacy.finding_id);
  await page.locator(`[data-di-select][value="${expired.finding_id}"]`).check();
  await page.locator('[data-di-bulk-preview]').click();
  const dialog = page.locator('[data-di-bulk]');
  await dialog.getByText(/1 repair\(s\) ready/).waitFor({ timeout: 15000 });
  check(await dialog.locator('[data-di-bulk-execute]').isDisabled(), 'bulk apply is disabled until confirmed');
  check(!/\bnull\b/.test(await dialog.locator('[data-di-bulk-body]').innerText()), 'bulk preview renders no placeholder text');
  await inspect(page, '390x844 bulk dialog');
  await shot(page, 'retro-390x844-bulk');
  await dialog.locator('[data-di-close]').click();                    // cancel the bulk repair
  state = await finding(page, expired.finding_id);
  check(state.status !== 'resolved' && state.live.detected, 'closing the bulk dialog changes nothing');

  // Explicit authorisation of the single legacy closure.
  await page.setViewportSize({ width: 1280, height: 800 });
  await openFindings(page);
  const confirmPanel = await investigate(page, legacy.finding_id);
  await confirmPanel.getByRole('button', { name: 'Preview fix' }).click();
  await confirmPanel.getByText('Assignments that will be closed').waitFor();
  await confirmPanel.getByLabel('I reviewed these changes and want to apply them').check();
  await confirmPanel.getByRole('button', { name: 'Apply fix' }).click();
  await confirmPanel.getByText('Repair applied and verified').waitFor({ timeout: 15000 });
  state = await finding(page, legacy.finding_id);
  check(state.status === 'resolved' && !state.live.detected, 'authorised legacy closure resolved the finding');
  await shot(page, 'retro-1280x800-applied');

  // Explicit bulk authorisation of the expired-lease closure. The preview is
  // slowed so the confirmation's state can be observed while it loads.
  await page.route(`**${api}/bulk/preview`, async route => { await new Promise(resolve => setTimeout(resolve, 1200)); await route.continue(); });
  await openFindings(page);
  await page.locator(`[data-di-select][value="${expired.finding_id}"]`).check();
  const bulkConfirm = dialog.locator('[data-di-bulk-confirm]');
  const bulkExecute = dialog.locator('[data-di-bulk-execute]');
  await page.locator('[data-di-bulk-preview]').click();
  check(await bulkConfirm.isDisabled() && !(await bulkConfirm.isChecked()), 'bulk confirmation is unavailable while the preview loads');
  await dialog.getByText(/1 repair\(s\) ready with 1 record change\(s\); 0 skipped/).waitFor({ timeout: 15000 });
  check(await bulkConfirm.isEnabled() && await bulkExecute.isDisabled(), 'bulk confirmation becomes available once the preview has loaded');
  await bulkConfirm.check();
  check(await bulkExecute.isEnabled(), 'confirming the loaded preview enables bulk apply');
  await dialog.locator('[data-di-close]').click();
  await page.locator('[data-di-bulk-preview]').click();                // a fresh preview replaces the reviewed one
  check(!(await bulkConfirm.isChecked()) && await bulkConfirm.isDisabled() && await bulkExecute.isDisabled(), 'a fresh preview resets the confirmation');
  await dialog.getByText(/1 repair\(s\) ready with 1 record change\(s\); 0 skipped/).waitFor({ timeout: 15000 });
  await page.unroute(`**${api}/bulk/preview`);
  await bulkConfirm.check();
  await bulkExecute.click();
  await dialog.getByText(/All 1 repairs applied/).waitFor({ timeout: 15000 });
  check(await bulkConfirm.isDisabled() && await bulkExecute.isDisabled(), 'an applied batch needs a new preview before confirming again');
  await inspect(page, '1280x800 bulk applied');
  await shot(page, 'retro-1280x800-bulk-applied');
  state = await finding(page, expired.finding_id);
  check(state.status === 'resolved', 'bulk authorisation resolved the expired-lease finding');

  // "Set asset hostname" repair: validation, CSRF and a real attributed apply.
  for (const viewport of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
    await page.setViewportSize(viewport);
    await page.goto(`${base}${page_path}?status=active&q=${encodeURIComponent('old-camera.example.invalid')}`, { waitUntil: 'networkidle' });
    const hostPanel = await investigate(page, hostname.finding_id);
    await hostPanel.getByRole('radio', { name: /Set asset hostname/ }).check();
    await hostPanel.getByLabel('Hostname or FQDN').fill('not a hostname');
    expect400();
    await hostPanel.getByRole('button', { name: 'Preview fix' }).click();
    await hostPanel.getByText(/valid hostname/i).waitFor({ timeout: 10000 });
    check(true, `${viewport.width}px: an invalid hostname is refused inline, not as a server error`);
    await hostPanel.getByLabel('Hostname or FQDN').fill('camera.example.invalid');
    await hostPanel.getByRole('button', { name: 'Preview fix' }).click();
    await hostPanel.getByText('Records that will change').waitFor();
    await inspect(page, `${viewport.width}x${viewport.height} hostname preview`);
    await shot(page, `hostname-repair-${viewport.width}x${viewport.height}-preview`);
    if (viewport.width === 390) { await collapse(page, hostname.finding_id); continue; }
    const token = await page.evaluate(async ([url]) => (await (await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.body.dataset.csrfToken },
      body: JSON.stringify({ action: 'set_asset_hostname', params: { hostname: 'camera.example.invalid' } }),
    })).json()).preview_token, [`${api}/findings/${hostname.finding_id}/preview`]);
    expect400();
    const csrfStatus = await page.evaluate(async ([url, previewToken]) => (await fetch(url, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': 'not-the-session-token' },
      body: JSON.stringify({ action: 'set_asset_hostname', params: { hostname: 'camera.example.invalid' }, preview_token: previewToken }),
    })).status, [`${api}/findings/${hostname.finding_id}/repair`, token]);
    check(csrfStatus === 400, `hostname repair with a wrong CSRF token is rejected (got ${csrfStatus})`);
    await hostPanel.getByLabel('I reviewed these changes and want to apply them').check();
    await hostPanel.getByRole('button', { name: 'Apply fix' }).click();
    await hostPanel.getByText(/Repair applied/).waitFor({ timeout: 15000 });
    check(true, 'hostname repair applied through the browser');
    await shot(page, 'hostname-repair-1280x800-applied');
  }
  await context.close();

  // ------------------------------------------------ administrator without repair permission
  const reviewContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const reviewer = await reviewContext.newPage();
  watch(reviewer, (path, status) => status === 403 && path.endsWith('/repair'));
  await login(reviewer, fixture.review_only_email);
  await reviewer.goto(`${base}${page_path}?status=all&q=${encodeURIComponent(legacy.asset_tag)}`, { waitUntil: 'networkidle' });
  check(await reviewer.locator('[data-di-bulk-preview]').count() === 0, 'review-only administrator has no bulk repair control');
  const repairStatus = await reviewer.evaluate(async ([url]) => (await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.body.dataset.csrfToken || '' },
    body: JSON.stringify({ action: 'close_obsolete_dhcp', preview_token: '0'.repeat(64) }),
  })).status, [`${api}/findings/${legacy.finding_id}/repair`]);
  check(repairStatus === 403, `review-only administrator repair returns 403 (got ${repairStatus})`);
  const hostnameStatus = await reviewer.evaluate(async ([url]) => (await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.body.dataset.csrfToken || '' },
    body: JSON.stringify({ action: 'set_asset_hostname', params: { hostname: 'reviewer.example.invalid' }, preview_token: '0'.repeat(64) }),
  })).status, [`${api}/findings/${hostname.finding_id}/repair`]);
  check(hostnameStatus === 403, `review-only administrator hostname repair returns 403 (got ${hostnameStatus})`);
  await reviewContext.close();

  // ------------------------------------------------ non-administrator
  const viewerContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const viewer = await viewerContext.newPage();
  watch(viewer, (path, status) => status === 403);
  await login(viewer, 'stage2b-viewer@example.invalid');
  const response = await viewer.goto(`${base}${page_path}`, { waitUntil: 'networkidle' });
  check(response.status() === 403 || !viewer.url().includes(page_path), `viewer cannot open Data Integrity (status ${response.status()})`);
  check(await viewer.locator('[data-di-investigate]').count() === 0, 'viewer sees no findings');
  const viewerRepair = await viewer.evaluate(async ([url]) => (await fetch(url, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': document.body.dataset.csrfToken || '' },
    body: JSON.stringify({ action: 'close_obsolete_dhcp', preview_token: '0'.repeat(64) }),
  })).status, [`${api}/findings/${expired.finding_id}/repair`]);
  check(viewerRepair === 403, `viewer repair returns 403 (got ${viewerRepair})`);
  await viewerContext.close();

  check(expected.http === 0 && expected.console === 0, 'every provoked 400 response was observed');
  if (evidence.httpErrors.length || evidence.consoleErrors.length || evidence.pageErrors.length || evidence.cspViolations.length) throw new Error(`browser diagnostics ${JSON.stringify(evidence)}`);
  await fs.writeFile(`${artifacts}/dhcp-retrospective-browser-results.json`, JSON.stringify({ status: 'PASS', ...evidence }, null, 2));
  console.log(JSON.stringify({ status: 'PASS', checks: evidence.checks.length, viewports: evidence.viewports, screenshots: evidence.screenshots }));
} finally {
  await browser.close();
}
