import fs from 'node:fs/promises';
import { chromium } from 'playwright';

const base = process.env.BASE_URL || 'http://127.0.0.1:18089';
const artifacts = process.env.ARTIFACT_DIR;
const password = process.env.ACCEPTANCE_PASSWORD || 'Stage2B-fixture-password-012345';
if (!artifacts) throw new Error('ARTIFACT_DIR is required');
await fs.mkdir(artifacts, { recursive: true });

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const evidence = { httpErrors: [], consoleErrors: [], pageErrors: [], cspViolations: [], screenshots: [], viewports: [] };

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

async function openNetwork(page) {
  await page.getByRole('tab', { name: /Network & identity/i }).click();
  await page.locator('#asset-panel-network').waitFor({ state: 'visible' });
}

async function save(page, hostname, managed = false) {
  await openNetwork(page);
  const input = page.locator('#asset-hostname');
  await input.fill(hostname);
  if (managed) {
    await page.getByLabel(/Also update associated Static IP/i).check();
    await page.locator('#managed-hostname-record').selectOption('9251');
  }
  await page.getByRole('button', { name: 'Save hostname' }).click();
  await page.waitForLoadState('networkidle');
  await openNetwork(page);
}

try {
  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
  const page = await context.newPage();
  let expectedCsrfFailure = false;
  page.on('response', response => { const path = new URL(response.url()).pathname; if (expectedCsrfFailure && path === '/infrastructure/asset-manager/9401/hostname' && response.status() === 422) { expectedCsrfFailure = false; return; } if (response.status() >= 400 && response.url().startsWith(base) && path !== '/favicon.ico') evidence.httpErrors.push({ status: response.status(), path }); });
  page.on('console', message => { if (message.type() === 'error' && !/responded with a status of 422/i.test(message.text())) { evidence.consoleErrors.push(message.text()); if (/content security policy|csp/i.test(message.text())) evidence.cspViolations.push(message.text()); } });
  page.on('pageerror', error => evidence.pageErrors.push(String(error)));
  await login(page, 'stage2b-admin@example.invalid');
  await page.goto(`${base}/infrastructure/asset-manager/9401`, { waitUntil: 'networkidle' });
  await openNetwork(page);
  if (!(await page.locator('#asset-hostname').isVisible())) throw new Error('administrator hostname editor not visible');
  await inspect(page, '1920x1080 initial');
  await page.screenshot({ path: `${artifacts}/hostname-1920x1080-initial.png`, fullPage: true }); evidence.screenshots.push('hostname-1920x1080-initial.png');

  await save(page, 'browser-managed.example.invalid');
  if (!(await page.locator('body').innerText()).includes('browser-managed.example.invalid')) throw new Error('new hostname missing from header/panel');
  if (!(await page.locator('body').innerText()).includes('old-browser.example.invalid')) throw new Error('historical revoked hostname missing');
  await page.screenshot({ path: `${artifacts}/hostname-1920x1080-saved.png`, fullPage: true }); evidence.screenshots.push('hostname-1920x1080-saved.png');

  const csrf = await page.locator('input[name="csrf_token"]').first().inputValue();
  expectedCsrfFailure = true;
  const csrfResult = await page.evaluate(async token => { const body = new FormData(); body.set('hostname', 'csrf-failure.example.invalid'); const response = await fetch('/infrastructure/asset-manager/9401/hostname', { method: 'POST', body }); return response.status; }, csrf);
  if (![400, 403, 422].includes(csrfResult)) throw new Error(`CSRF failure returned ${csrfResult}`);

  await save(page, 'browser-managed.example.invalid', true);
  const profile = await page.evaluate(async () => (await fetch('/infrastructure/asset-manager/9401/profile')).json());
  if (!profile.managed_ips.some(row => row.id === 9251 && row.name === 'browser-managed.example.invalid')) throw new Error('managed record hostname was not updated');

  await page.setViewportSize({ width: 1280, height: 800 });
  await page.reload({ waitUntil: 'networkidle' }); await openNetwork(page); await inspect(page, '1280x800');
  await save(page, 'browser-replaced.example.invalid');
  await page.screenshot({ path: `${artifacts}/hostname-1280x800-replaced.png`, fullPage: true }); evidence.screenshots.push('hostname-1280x800-replaced.png');

  await openNetwork(page);
  const input = page.locator('#asset-hostname');
  await input.fill('invalid hostname');
  if (await input.evaluate(node => node.validity.valid)) throw new Error('invalid hostname was accepted by browser validation');
  if (await input.inputValue() !== 'invalid hostname') throw new Error('invalid hostname draft was not preserved');
  await page.getByRole('button', { name: 'Cancel' }).click();
  if (await input.inputValue() !== 'browser-replaced.example.invalid') throw new Error('cancel did not restore saved hostname');

  await save(page, '');
  const cleared = await page.locator('body').innerText();
  if (!cleared.includes('Not recorded') || !cleared.includes('old-browser.example.invalid')) throw new Error('clear did not remove preferred hostname while preserving history');

  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload({ waitUntil: 'networkidle' }); await openNetwork(page); await inspect(page, '390x844');
  await page.screenshot({ path: `${artifacts}/hostname-390x844.png`, fullPage: true }); evidence.screenshots.push('hostname-390x844.png');
  await context.close();

  const viewerContext = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const viewer = await viewerContext.newPage();
  await login(viewer, 'stage2b-viewer@example.invalid');
  await viewer.goto(`${base}/infrastructure/asset-manager/9401`, { waitUntil: 'networkidle' });
  if (await viewer.locator('#asset-hostname').count() !== 0) throw new Error('non-administrator saw hostname editor');
  const viewerStatus = await viewer.evaluate(async () => { const body = new FormData(); body.set('hostname', 'viewer-change.example.invalid'); return (await fetch('/infrastructure/asset-manager/9401/hostname', { method: 'POST', body })).status; });
  if (viewerStatus !== 403) throw new Error(`non-administrator mutation returned ${viewerStatus}`);
  await viewerContext.close();

  if (evidence.httpErrors.length || evidence.consoleErrors.length || evidence.pageErrors.length || evidence.cspViolations.length) throw new Error(`browser diagnostics ${JSON.stringify(evidence)}`);
  await fs.writeFile(`${artifacts}/hostname-browser-results.json`, JSON.stringify({ status: 'PASS', ...evidence }, null, 2));
  console.log(JSON.stringify({ status: 'PASS', ...evidence }));
} finally {
  await browser.close();
}
