import { chromium } from 'playwright';

const base = process.env.BASE_URL || 'http://127.0.0.1:18080';
const browser = await chromium.launch({headless: true});
const page = await browser.newPage({viewport: {width: 1440, height: 1000}});
const consoleErrors = [];
page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });
page.on('pageerror', error => consoleErrors.push(String(error)));
const result = {steps: [], consoleErrors};
const mark = (name, value) => result.steps.push({name, value});

await page.goto(`${base}/setup`, {waitUntil: 'networkidle'});
if (await page.locator('form[action="/setup"]').count()) {
  await page.getByLabel('First name').fill('Stage');
  await page.getByLabel('Last name').fill('Acceptance');
  await page.getByLabel('Email').fill('stage4a-admin@example.invalid');
  await page.getByLabel('Setup token').fill('stage4a-setup-token');
  await page.getByLabel('Password', {exact: true}).fill('Stage4A-password-012345');
  await page.getByLabel('Confirm password').fill('Stage4A-password-012345');
  await page.getByRole('button', {name: 'Create administrator'}).click();
  await page.waitForLoadState('networkidle');
}
if (!new URL(page.url()).pathname.endsWith('/login')) throw new Error(`setup did not reach login: ${page.url()}`);
mark('setup', 'administrator created');

await page.getByLabel('Email').fill('stage4a-admin@example.invalid');
await page.getByLabel('Password', {exact: true}).fill('Stage4A-password-012345');
await page.getByRole('button', {name: 'Sign in'}).click();
await page.waitForLoadState('networkidle');
mark('login', page.url());

await page.goto(`${base}/networking/vlan-ip-manager/new`, {waitUntil: 'networkidle'});
await page.getByLabel('IP Address').fill('192.0.2.47');
await page.getByLabel('Name', {exact: true}).fill('Stage 4A Disposable Device');
await page.getByLabel('Description').fill('Synthetic acceptance fixture');
await page.getByRole('button', {name: 'Save'}).click();
await page.waitForLoadState('networkidle');
const idMatch = page.url().match(/vlan-ip-manager\/(\d+)$/);
if (!idMatch) { console.log(await page.locator('body').innerText()); throw new Error(`record creation did not reach detail: ${page.url()}`); }
const recordId = Number(idMatch[1]);
mark('record_created', recordId);
if (!(await page.locator('text=Network Traffic Disabled').count())) throw new Error('default disabled status not rendered');
await page.screenshot({path: '/artifacts/stage4a-device-disabled.png', fullPage: true});

await page.goto(`${base}/networking/vlan-ip-manager/${recordId}/edit`, {waitUntil: 'networkidle'});
const traffic = page.locator('[name="traffic_monitoring_enabled"]');
await traffic.check();
await page.getByRole('button', {name: 'Save'}).click();
await page.waitForLoadState('networkidle');
let status = await page.evaluate(async id => (await fetch(`/networking/vlan-ip-manager/${id}/network-traffic`)).json(), recordId);
mark('enabled', status);
if (!status.enabled) throw new Error('API did not report enabled');
await page.screenshot({path: '/artifacts/stage4a-device-enabled.png', fullPage: true});

const csrfFailure = await page.evaluate(async id => {
  const response = await fetch(`/networking/vlan-ip-manager/${id}/network-traffic`, {method: 'PUT', headers: {'content-type': 'application/json'}, body: JSON.stringify({enabled: false})});
  return response.status;
}, recordId);
mark('csrf_without_token', csrfFailure);
if (![400, 403].includes(csrfFailure)) throw new Error(`CSRF mutation was not rejected: ${csrfFailure}`);

await page.goto(`${base}/networking/vlan-ip-manager/${recordId}/edit`, {waitUntil: 'networkidle'});
await page.locator('[name="traffic_monitoring_enabled"]').uncheck();
await page.getByRole('button', {name: 'Save'}).click();
await page.waitForLoadState('networkidle');
status = await page.evaluate(async id => (await fetch(`/networking/vlan-ip-manager/${id}/network-traffic`)).json(), recordId);
mark('disabled', status);
if (status.enabled) throw new Error('API did not report disabled');

await page.goto(`${base}/networking/vlan-ip-manager/${recordId}/edit`, {waitUntil: 'networkidle'});
await page.locator('[name="traffic_monitoring_enabled"]').check();
await page.getByRole('button', {name: 'Save'}).click();
await page.waitForLoadState('networkidle');
status = await page.evaluate(async id => (await fetch(`/networking/vlan-ip-manager/${id}/network-traffic`)).json(), recordId);
mark('reenabled', status);
await page.screenshot({path: '/artifacts/stage4a-device-reenabled.png', fullPage: true});

await page.setViewportSize({width: 390, height: 844});
await page.goto(`${base}/networking/vlan-ip-manager/${recordId}`, {waitUntil: 'networkidle'});
await page.screenshot({path: '/artifacts/stage4a-device-mobile.png', fullPage: true});
mark('mobile', {width: 390, height: 844, horizontalOverflow: await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)});
mark('console_errors', consoleErrors.filter(error => !error.includes('400')));
console.log(JSON.stringify({...result, recordId}));
await browser.close();
