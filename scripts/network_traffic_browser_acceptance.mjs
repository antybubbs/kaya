import fs from 'node:fs/promises';
import { chromium } from 'playwright';

const base = process.env.BASE_URL || 'http://127.0.0.1:18080';
const artifacts = process.env.ARTIFACT_DIR || 'stage4-artifacts/network-traffic-browser';
const phase = process.env.ACCEPTANCE_PHASE || 'empty';
const email = process.env.ACCEPTANCE_ADMIN_EMAIL || 'network-browser-admin@example.invalid';
const password = process.env.ACCEPTANCE_ADMIN_PASSWORD || 'NetworkBrowser-password-012345';
const setupToken = process.env.ACCEPTANCE_SETUP_TOKEN || 'network-browser-setup-token';
const sourceName = process.env.ACCEPTANCE_SOURCE_NAME || 'Cisco NSEL Browser Fixture';

await fs.mkdir(artifacts, { recursive: true });
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const consoleErrors = [];
const failures = [];
page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
page.on('pageerror', error => consoleErrors.push(String(error)));
const check = (condition, message) => { if (!condition) { failures.push(message); throw new Error(message); } };
const noOverflow = async label => {
  const result = await page.evaluate(() => ({ width: window.innerWidth, scrollWidth: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth }));
  check(result.scrollWidth <= result.width + 1 && result.bodyWidth <= result.width + 1, `${label} has horizontal overflow: ${JSON.stringify(result)}`);
  return result;
};
const shot = name => page.screenshot({ path: `${artifacts}/${name}.png`, fullPage: true });

try {
  await page.goto(`${base}/setup`, { waitUntil: 'networkidle' });
  if (await page.locator('form[action="/setup"]').count()) {
    await page.getByLabel('First name').fill('Network');
    await page.getByLabel('Last name').fill('Browser Admin');
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Setup token').fill(setupToken);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByLabel('Confirm password').fill(password);
    await page.getByRole('button', { name: 'Create administrator' }).click();
    await page.waitForLoadState('networkidle');
  }
  if (phase === 'empty') {
    check(new URL(page.url()).pathname.endsWith('/login'), `setup did not reach login: ${page.url()}`);
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForLoadState('networkidle');
  } else {
    await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
    await page.getByLabel('Email').fill(email);
    await page.getByLabel('Password', { exact: true }).fill(password);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await page.waitForLoadState('networkidle');
  }

  await page.goto(`${base}/networking/ip-wan-monitor/traffic`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  const overview = page.locator('[data-traffic-app]');
  const overviewText = await overview.innerText();
  check(overviewText.includes('WAN bandwidth'), 'Overview does not separate WAN bandwidth');
  check(overviewText.includes('Flow collection'), 'Overview does not separate flow collection');
  check(overviewText.includes('Device usage'), 'Overview does not separate device usage');
  if (phase === 'empty') {
    check(overviewText.includes('WAN monitoring not configured'), 'WAN empty state is not informative');
    check(overviewText.includes('No tracked devices have persisted usage'), 'Device empty state is not informative');
  } else {
    check(overviewText.includes('1000 B'), 'Populated download total is not displayed');
    check(overviewText.includes('300 B'), 'Populated upload total is not displayed');
  }
  await noOverflow('desktop Overview');
  await shot(`network-traffic-${phase}-overview-desktop`);

  await page.goto(`${base}/networking/ip-wan-monitor/traffic/sources/manage`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  if (phase === 'empty') {
    const sourcesAfterCreate = await page.evaluate(async () => (await fetch('/networking/ip-wan-monitor/traffic/sources')).json());
    let created = sourcesAfterCreate.sources.find(source => source.provider_key === 'cisco_nsel');
    if (!created) {
      await page.getByRole('button', { name: 'Add source' }).click();
      await page.getByLabel('Source name').fill(sourceName);
      await page.getByLabel('Provider').selectOption('cisco_nsel');
      await page.getByLabel('Collector UDP port').fill('2055');
      await page.getByLabel('Authorised exporter IPs').fill('192.0.2.1');
      await page.getByLabel(/Enable flow collection/).check();
      await page.getByRole('button', { name: 'Save source' }).click();
      await page.waitForTimeout(500);
      const refreshed = await page.evaluate(async () => (await fetch('/networking/ip-wan-monitor/traffic/sources')).json());
      created = refreshed.sources.find(source => source.provider_key === 'cisco_nsel');
    }
    check(created, 'Cisco NSEL source was not created');
    check(created.health_state !== 'unconfigured', `Cisco NSEL source incorrectly shows Unconfigured: ${created.health_state}`);
    await page.getByRole('button', { name: 'Edit' }).first().click();
    await page.getByLabel('Source name').fill(`${sourceName} Edited`);
    await page.getByRole('button', { name: 'Save source' }).click();
    await page.waitForTimeout(400);
    check((await page.locator('[data-source-list]').innerText()).includes(`${sourceName} Edited`), 'Source edit was not persisted');
  }
  await noOverflow('desktop Sources');
  await shot(`network-traffic-${phase}-sources-desktop`);

  const sourcePayload = await page.evaluate(async () => (await fetch('/networking/ip-wan-monitor/traffic/sources')).json());
  const source = sourcePayload.sources.find(item => item.provider_key === 'cisco_nsel');
  check(source, 'Cisco NSEL source is missing from Sources');
  const overviewPayload = await page.evaluate(async () => (await fetch('/networking/ip-wan-monitor/traffic/overview')).json());
  const overviewSource = overviewPayload.sources.find(item => item.id === source.id);
  check(overviewSource?.health_state === source.health_state, 'Sources and Overview health states differ');

  await page.goto(`${base}/networking/ip-wan-monitor/traffic/settings`, { waitUntil: 'networkidle' });
  check(await page.getByText('Network Traffic settings').count() === 1, 'Settings page did not load');
  await noOverflow('desktop Settings');
  await shot(`network-traffic-${phase}-settings-desktop`);

  await page.goto(`${base}/networking/ip-wan-monitor/traffic/diagnostics/view`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  check(await page.getByText('Flow collector diagnostics').count() === 1, 'Diagnostics page did not load');
  const closedDetails = await page.locator('details').evaluateAll(nodes => nodes.filter(node => !node.open).length);
  check(closedDetails > 0, 'Diagnostics lifecycle details are not collapsed by default');
  await noOverflow('desktop Diagnostics');
  await shot(`network-traffic-${phase}-diagnostics-desktop`);

  const csrfStatus = await page.evaluate(async () => {
    const response = await fetch('/networking/ip-wan-monitor/traffic/config', { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ is_enabled: true }) });
    return response.status;
  });
  check([400, 403].includes(csrfStatus), `CSRF protection returned unexpected status ${csrfStatus}`);

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${base}/networking/ip-wan-monitor/traffic`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  await noOverflow('mobile Overview');
  await shot(`network-traffic-${phase}-overview-mobile`);
  await page.goto(`${base}/networking/ip-wan-monitor/traffic/diagnostics/view`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(400);
  await noOverflow('mobile Diagnostics');
  await shot(`network-traffic-${phase}-diagnostics-mobile`);

  const unexpectedConsoleErrors = consoleErrors.filter(error => !(
    csrfStatus === 400 && error.includes('responded with a status of 400')
  ));
  check(unexpectedConsoleErrors.length === 0, `Browser console errors: ${JSON.stringify(unexpectedConsoleErrors)}`);
  console.log(JSON.stringify({ phase, sourceHealth: source.health_state, overviewHealth: overviewSource.health_state, csrfStatus, consoleErrors, failures }));
} finally {
  await browser.close();
}
