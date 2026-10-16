import fs from 'node:fs/promises';
import { chromium } from 'playwright';

const base = process.env.BASE_URL || 'http://127.0.0.1:18080';
const recordId = process.env.ACCEPTANCE_RECORD_ID;
const artifacts = process.env.ARTIFACT_DIR || 'stage4-artifacts/device-traffic-browser';
const email = process.env.ACCEPTANCE_ADMIN_EMAIL || 'device-traffic-admin@example.invalid';
const password = process.env.ACCEPTANCE_ADMIN_PASSWORD || 'DeviceTraffic-password-012345';
const setupToken = process.env.ACCEPTANCE_SETUP_TOKEN || 'device-traffic-setup-token';

if (!recordId) throw new Error('ACCEPTANCE_RECORD_ID is required');
await fs.mkdir(artifacts, { recursive: true });
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const errors = [];
page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
page.on('pageerror', error => errors.push(String(error)));

try {
  await page.goto(`${base}/setup`, { waitUntil: 'networkidle' });
  if (await page.locator('form[action="/setup"]').count()) {
    await page.getByLabel('First name').fill('Device');
    await page.getByLabel('Last name').fill('Traffic Admin');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Setup token').fill(setupToken);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByLabel('Confirm password').fill(password);
    await page.getByRole('button', { name: 'Create administrator' }).click();
    await page.waitForLoadState('networkidle');
  }
  await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForLoadState('networkidle');
  await page.goto(`${base}/networking/vlan-ip-manager/${encodeURIComponent(recordId)}`, { waitUntil: 'networkidle' });

  const toggle = page.locator('[data-device-traffic-toggle-input]');
  if (await toggle.count() !== 1) throw new Error('Administrator Network Traffic switch is not rendered');
  if (await toggle.isChecked()) throw new Error('Fixture unexpectedly started enabled');
  const reportHref = await page.locator('[data-device-traffic-card] a').getAttribute('href');
  if (reportHref !== `/networking/ip-wan-monitor/traffic?device_id=${recordId}`) throw new Error(`Device report link is incorrect: ${reportHref}`);

  await toggle.check();
  await page.reload({ waitUntil: 'networkidle' });
  if (!(await page.locator('[data-device-traffic-toggle-input]').isChecked())) throw new Error('Enable state was not reflected after save');
  if ((await page.locator('[data-device-traffic-state]').innerText()).trim().toLowerCase() === 'disabled') throw new Error('Enabled status was not reflected');
  await page.screenshot({ path: `${artifacts}/device-traffic-enabled.png`, fullPage: true });

  await page.locator('[data-device-traffic-toggle-input]').uncheck();
  await page.reload({ waitUntil: 'networkidle' });
  if (await page.locator('[data-device-traffic-toggle-input]').isChecked()) throw new Error('Disable state was not reflected after save');
  if ((await page.locator('[data-device-traffic-state]').innerText()).trim().toLowerCase() !== 'disabled') throw new Error('Disabled status was not reflected');
  await page.screenshot({ path: `${artifacts}/device-traffic-disabled.png`, fullPage: true });
  const overflow = await page.evaluate(() => ({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth }));
  if (overflow.scrollWidth > overflow.width + 1) throw new Error(`Device detail has horizontal overflow: ${JSON.stringify(overflow)}`);
  console.log(JSON.stringify({ recordId, errors, failures: [] }));
} finally {
  await browser.close();
}
