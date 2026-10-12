import { chromium } from 'playwright';

const base = process.env.BASE_URL || 'http://127.0.0.1:18080';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const errors = [];
page.on('pageerror', error => errors.push(String(error)));
await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
await page.getByLabel('Email').fill('stage4a-admin@example.invalid');
await page.getByLabel('Password', { exact: true }).fill('Stage4A-password-012345');
await page.getByRole('button', { name: 'Sign in' }).click();
await page.waitForLoadState('networkidle');

await page.goto(`${base}/networking/ip-wan-monitor/traffic`, { waitUntil: 'networkidle' });
console.log('traffic-loaded');
await page.screenshot({ path: '/artifacts/stage4b-overview.png', fullPage: true });
const overviewText = await page.locator('[data-traffic-app]').innerText();
await page.locator('[data-traffic-range]').selectOption('7d');
await page.waitForTimeout(300);
console.log('range-selected');
await page.screenshot({ path: '/artifacts/stage4b-overview-7d.png', fullPage: true });
await page.locator('[data-traffic-range]').selectOption('24h');
await page.waitForTimeout(300);
const deviceRows = await page.locator('[data-device-rows] tr').count();
console.log(`device-rows:${deviceRows}`);
console.log(`device-buttons:${await page.locator('[data-device-select]').evaluateAll(nodes => nodes.map(node => node.getAttribute('data-device-select')).join(','))}`);
await page.locator('[data-device-sort]').selectOption('download');
console.log('sort-selected');
await page.locator('[data-device-select="1"]').click();
await page.waitForTimeout(300);
console.log('device-selected');
const deviceHistoryVisible = await page.locator('[data-device-detail]').isVisible();
await page.screenshot({ path: '/artifacts/stage4b-device-history.png', fullPage: true });
const report = await page.evaluate(async () => {
  const response = await fetch('/networking/ip-wan-monitor/traffic/report?range=24h');
  return { status: response.status, body: await response.json() };
});

await page.goto(`${base}/networking/vlan-ip-manager/1`, { waitUntil: 'networkidle' });
await page.screenshot({ path: '/artifacts/stage4b-device-card.png', fullPage: true });
const result = {
  overviewHasDevices: overviewText.includes('Opted-in devices'),
  reportStatus: report.status,
  reportRange: report.body.wan?.range,
  deviceRows,
  deviceHistoryVisible,
  horizontalOverflow: await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth),
  consoleErrors: errors,
};
console.log(JSON.stringify(result));
await browser.close();
