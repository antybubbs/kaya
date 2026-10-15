import fs from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { chromium } from 'playwright';

const base = process.env.BASE_URL || 'http://127.0.0.1:18080';
const artifacts = process.env.ARTIFACT_DIR;
const fixtureFile = process.env.FIXTURE_FILE;
const sqlCountFile = process.env.SQL_COUNT_FILE;
const adminEmail = process.env.ACCEPTANCE_ADMIN_EMAIL;
const viewerEmail = process.env.ACCEPTANCE_VIEWER_EMAIL;
const password = process.env.ACCEPTANCE_PASSWORD;
if (!artifacts || !fixtureFile || !adminEmail || !viewerEmail || !password) {
  throw new Error('ARTIFACT_DIR, FIXTURE_FILE, ACCEPTANCE_ADMIN_EMAIL, ACCEPTANCE_VIEWER_EMAIL and ACCEPTANCE_PASSWORD are required');
}
const fixture = JSON.parse(await fs.readFile(fixtureFile, 'utf8'));
const expected = { sources: 2, vlans: 2, mappings: 2, assets: 14, observations: 65, dns_clients: 4, dhcp_leases: 4, device_aggregates: 2 };
for (const [key, value] of Object.entries(expected)) if (fixture[key] !== value) throw new Error(`Fixture mismatch for ${key}: ${fixture[key]}`);
await fs.mkdir(artifacts, { recursive: true });

const results = [];
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const contexts = new Set();
const evidence = { http: [], console: [], pageErrors: [], timings: [] };

async function session(email, mobile = false) {
  const context = await browser.newContext({ viewport: mobile ? { width: 390, height: 844 } : { width: 1440, height: 1000 } });
  contexts.add(context);
  const page = await context.newPage();
  page.on('response', response => { if (response.url().startsWith(base)) evidence.http.push({ status: response.status(), url: new URL(response.url()).pathname }); });
  page.on('console', message => { if (message.type() === 'error') { evidence.console.push(message.text()); } });
  page.on('pageerror', error => evidence.pageErrors.push(String(error)));
  await page.goto(`${base}/login`, { waitUntil: 'networkidle' });
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForLoadState('networkidle');
  return page;
}

async function screenshot(page, name) { await page.screenshot({ path: `${artifacts}/${name}.png`, fullPage: true }); }
async function assertPage(page, path, checks, name) {
  const started = performance.now();
  const response = await page.goto(`${base}${path}`, { waitUntil: 'networkidle' });
  const body = await page.locator('body').innerText();
  for (const check of checks) if (!check.test(body)) throw new Error(`${name}: missing ${check}`);
  const layout = await page.evaluate(() => ({ width: innerWidth, scrollWidth: document.documentElement.scrollWidth, bodyWidth: document.body.scrollWidth, nestedForms: document.querySelectorAll('form form').length }));
  if (layout.scrollWidth > layout.width + 1 || layout.bodyWidth > layout.width + 1) throw new Error(`${name}: horizontal overflow ${JSON.stringify(layout)}`);
  if (layout.nestedForms) throw new Error(`${name}: nested forms detected`);
  evidence.timings.push({ name, milliseconds: Math.round(performance.now() - started), status: response.status() });
  return { response, body };
}

async function run(name, fn) {
  const started = Date.now();
  try { await fn(); results.push({ name, status: 'PASS', milliseconds: Date.now() - started }); }
  catch (error) { results.push({ name, status: 'FAIL', error: String(error), milliseconds: Date.now() - started }); }
}

try {
  const admin = await session(adminEmail);
  await run('device-usage-search-sort-pagination-and-periods', async () => {
    await assertPage(admin, '/networking/ip-wan-monitor/traffic/devices', [/Device Usage/i], 'device usage');
    const report = async query => admin.evaluate(async queryString => (await fetch(`/networking/ip-wan-monitor/traffic/device-usage?${queryString}`)).json(), query);
    const customQuery = 'range=custom&start=2026-01-15T00:00:00&end=2026-01-15T23:59:00';
    const custom = await report(customQuery);
    if (custom.summary.download_bytes !== 1000 || custom.summary.upload_bytes !== 300) throw new Error(`unexpected populated totals ${JSON.stringify(custom.summary)}`);
    if (custom.page_count < 1 || custom.page_size < 1) throw new Error('pagination metadata missing');
    for (const period of ['24h', '7d', '30d', '90d']) {
      const response = await report(`range=${period}`);
      if (!response.range) throw new Error(`period ${period} was not accepted`);
    }
    const searched = await report(`${customQuery}&q=192.0.2.10`);
    if (searched.total < 1) throw new Error('search returned no matching fixture endpoint');
    const sorted = await report(`${customQuery}&sort=download`);
    if (!Array.isArray(sorted.devices)) throw new Error('sort response missing devices');
    const secondPage = await report(`${customQuery}&page=2`);
    if (secondPage.page !== 2 && secondPage.page_count > 1) throw new Error('pagination did not advance');
    await screenshot(admin, 'device-usage-desktop');
  });
  await run('dns-confirmed-and-unlinked-navigation', async () => {
    const page = admin;
    await assertPage(page, '/networking/dns-manager?tab=dhcp', [/DHCP/i, /Review \/ Adopt/i], 'DHCP list');
    const dhcpReviewLink = page.locator('a[href*="candidate_id=dhcp:"]').first();
    if (await dhcpReviewLink.count() !== 1) throw new Error('active DHCP lease has no Review / Adopt action');
    await dhcpReviewLink.click();
    await page.waitForLoadState('networkidle');
    const dhcpReviewBody = await page.locator('body').innerText();
    if (!dhcpReviewBody.match(/Observed identity/i) || !dhcpReviewBody.match(/DHCP identifiers/i)) throw new Error('DHCP evidence missing from shared review');
    await assertPage(page, '/networking/dns-manager?tab=clients', [/Clients/i, /Stage2B DNS/], 'DNS clients');
    const confirmedId = fixture.dns_client_ids[0];
    await page.goto(`${base}/networking/dns-manager/clients/${confirmedId}`, { waitUntil: 'networkidle' });
    const assetLink = page.locator('a[href="/infrastructure/asset-manager/9401"]');
    if (await assetLink.count() !== 1) throw new Error('confirmed DNS client has no Asset Profile link');
    await assetLink.click();
    await page.waitForLoadState('networkidle');
    if (!page.url().endsWith('/infrastructure/asset-manager/9401')) throw new Error(`DNS navigation ended at ${page.url()}`);
    const unlinkedId = fixture.dns_client_ids.at(-1);
    await assertPage(page, `/networking/dns-manager/clients/${unlinkedId}`, [/DNS traffic history/i], 'DNS detail');
    const reviewLink = page.locator('a[href*="candidate_id=dns:"]');
    if (await reviewLink.count() !== 1) throw new Error('unlinked DNS client has no Review / Adopt action');
    await reviewLink.click();
    await page.waitForLoadState('networkidle');
    const reviewBody = await page.locator('body').innerText();
    if (!reviewBody.match(/Observed identity/i) || !reviewBody.match(/DHCP identifiers/i)) throw new Error('DNS candidate evidence missing from shared review');
    page.once('dialog', dialog => dialog.accept());
    await page.getByRole('button', { name: /Adopt discovery/i }).click();
    await page.waitForLoadState('networkidle');
    if (!page.url().match(/\/infrastructure\/asset-manager\/\d+$/)) throw new Error(`DNS adoption ended at ${page.url()}`);
    await page.goto(`${base}/networking/dns-manager/clients/${unlinkedId}`, { waitUntil: 'networkidle' });
    if (await page.getByRole('link', { name: /Open unified Asset Profile/i }).count() !== 1) throw new Error('adopted DNS client has no Asset Profile link');
  });
  await run('vlan-detail-and-asset-navigation', async () => {
    await assertPage(admin, '/networking/vlan-ip-manager/9251', [/Network Traffic/i], 'VLAN/IP detail');
    await assertPage(admin, '/infrastructure/asset-manager/9401', [/Historical reporting/i, /Network Traffic/i], 'Asset Profile');
  });
  await run('static-context-enable-disable-and-csrf', async () => {
    const page = admin;
    await page.goto(`${base}/infrastructure/asset-manager/9450`, { waitUntil: 'networkidle' });
    const contextForm = page.locator('[data-traffic-context-form]');
    if (await contextForm.count() !== 1) throw new Error('source-context form missing');
    await contextForm.locator('select[name="mapping_id"]').selectOption({ index: 1 });
    const contextResponse = await Promise.all([page.waitForResponse(response => response.url().includes('/source-context')), contextForm.getByRole('button', { name: /Confirm source context/i }).click()]);
    if (contextResponse[0].status() !== 303) throw new Error(`context status ${contextResponse[0].status()}`);
    await page.waitForLoadState('networkidle');
    if (!(await page.locator('body').innerText()).match(/Monitoring\s+Disabled/i)) throw new Error('context confirmation enabled monitoring');
    const noCsrf = await page.request.post(`${base}/infrastructure/asset-manager/9450/network-traffic`, { form: { enabled: '1', csrf_token: '' } });
    if (![400, 403, 422].includes(noCsrf.status())) throw new Error(`CSRF status ${noCsrf.status()}`);
    const enable = page.locator('form[action$="/network-traffic"]');
    const enabledResponse = await Promise.all([page.waitForResponse(response => response.url().endsWith('/network-traffic')), enable.getByRole('button', { name: /Enable monitoring/i }).click()]);
    if (enabledResponse[0].status() !== 303) throw new Error(`enable status ${enabledResponse[0].status()}`);
    await page.waitForLoadState('networkidle');
    if (!(await page.locator('body').innerText()).match(/Active|Awaiting data/i)) throw new Error('enabled state missing');
    const disable = page.locator('form[action$="/network-traffic"]');
    await disable.getByRole('button', { name: /Disable monitoring/i }).click();
    await page.waitForLoadState('networkidle');
    if (!(await page.locator('body').innerText()).match(/Disabled/i)) throw new Error('disabled state missing');
  });
  await run('doorbell-monitoring-consistency', async () => {
    // Ring-doorbell-style device: DHCP identity, source-less adoption assignment
    // and an administrator-confirmed Cisco context for the same address.
    const page = admin;
    const address = '192.0.2.115';
    const doorbellUrl = '/infrastructure/asset-manager/9460';
    const helper = mode => JSON.parse(execFileSync(process.env.KAYA_STAGE2B_PYTHON, ['scripts/stage2b_seed_doorbell_flows.py', ...(mode ? [mode] : [])], { encoding: 'utf8' }).trim().split('\n').at(-1));
    // The fixture's site timezone is UTC, so the custom range is entered in UTC.
    const utcNow = () => new Date().toISOString().slice(0, 16);
    const usageRow = async () => {
      await page.goto(`${base}/networking/ip-wan-monitor/traffic/devices`, { waitUntil: 'networkidle' });
      await page.locator('[data-device-usage-range]').selectOption('custom');
      await page.locator('[data-device-usage-search]').fill(address);
      // Set both bounds before one change event; each field otherwise requests on its own.
      await page.evaluate(([start, end]) => { document.querySelector('[data-device-usage-start]').value = start; document.querySelector('[data-device-usage-end]').value = end; }, ['2026-01-14T00:00', utcNow()]);
      await Promise.all([
        page.waitForResponse(response => response.url().includes('/traffic/device-usage') && response.url().includes('range=custom') && response.url().includes(encodeURIComponent(address))),
        page.locator('[data-device-usage-end]').dispatchEvent('change'),
      ]);
      await page.waitForLoadState('networkidle');
      const rows = page.locator('.device-usage-table tbody tr').filter({ hasText: address });
      if (await rows.count() !== 1) throw new Error(`expected one Device Usage row for ${address}, found ${await rows.count()}`);
      const cells = (await rows.first().locator('th, td').allInnerTexts()).map(text => text.replace(/\s+/g, ' ').trim());
      return { row: rows.first(), cells, identity: cells[1], download: cells[4], upload: cells[5], observed: cells[8] };
    };
    const profileBody = async () => { await page.goto(`${base}${doorbellUrl}`, { waitUntil: 'networkidle' }); return (await page.locator('#asset-traffic').innerText()).replace(/\s+/g, ' '); };
    const api = async () => page.evaluate(async query => (await fetch(`/networking/ip-wan-monitor/traffic/device-usage?${query}`)).json(), `range=24h&q=${address}`);

    // 1-3: recognised, linked to its asset, and not yet monitored.
    let usage = await usageRow();
    if (!usage.identity.includes('Stage2B Doorbell')) throw new Error(`identity cell: ${usage.identity}`);
    if (!usage.identity.includes('Not monitored') || usage.download !== 'Not monitored') throw new Error(`initial state: ${JSON.stringify(usage.cells)}`);
    if (!/^\d+%$/.test(usage.observed)) throw new Error(`observed share cell: ${usage.observed}`);
    // 4: the identity link opens the permanent asset record.
    await Promise.all([page.waitForURL(`**${doorbellUrl}`), usage.row.getByRole('link', { name: 'Stage2B Doorbell' }).click()]);
    // 5: confirmed source-scoped assignment and monitoring disabled.
    const assetBody = await page.locator('body').innerText();
    if (!assetBody.includes(address)) throw new Error('assignment address missing from Asset Profile');
    if (!/Monitoring\s+Disabled/i.test(assetBody)) throw new Error('doorbell monitoring was not disabled before the journey');
    // 6: enable explicitly.
    const enabled = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/9460/network-traffic')),
      page.locator('form[action$="/network-traffic"]').getByRole('button', { name: /Enable monitoring/i }).click(),
    ]);
    if (enabled[0].status() !== 303) throw new Error(`enable status ${enabled[0].status()}`);
    // 7: both screens agree that monitoring is enabled and awaiting data.
    if (!/Monitoring Awaiting Data/i.test(await profileBody())) throw new Error('Asset Profile is not awaiting data after enabling');
    usage = await usageRow();
    if (!usage.identity.includes('Enabled — awaiting data') || usage.download !== 'Awaiting data') throw new Error(`Device Usage after enabling: ${JSON.stringify(usage.cells)}`);
    // 8: synthetic NSEL flows through the real attribution path.
    const seeded = helper();
    if (JSON.stringify(seeded.attributed) !== JSON.stringify([1, 1, 0])) throw new Error(`attribution ${JSON.stringify(seeded)}`);
    // 9-10: measured usage appears in both reporting paths and reconciles.
    usage = await usageRow();
    if (!usage.identity.includes('Monitored') || usage.download === 'Awaiting data') throw new Error(`Device Usage after flows: ${JSON.stringify(usage.cells)}`);
    const measured = (await api()).devices.filter(row => row.address === address);
    if (measured.length !== 1 || measured[0].download_bytes !== seeded.expected_download || measured[0].upload_bytes !== seeded.expected_upload) throw new Error(`Device Usage totals ${JSON.stringify(measured)}`);
    const profile = await profileBody();
    if (!/Monitoring Active/i.test(profile)) throw new Error(`Asset Profile status after flows: ${profile.slice(0, 200)}`);
    if (!profile.includes(`Download ${seeded.expected_download} bytes`) || !profile.includes(`Upload ${seeded.expected_upload} bytes`)) throw new Error(`Asset Profile totals: ${profile}`);
    await screenshot(page, 'doorbell-asset-profile-measured');
    // 11-12: disable; both screens agree.
    await page.locator('form[action$="/network-traffic"]').getByRole('button', { name: /Disable monitoring/i }).click();
    await page.waitForLoadState('networkidle');
    if (!/Monitoring Disabled/i.test(await profileBody())) throw new Error('Asset Profile not disabled');
    usage = await usageRow();
    if (!usage.identity.includes('Not monitored') || usage.download !== 'Not monitored') throw new Error(`Device Usage after disabling: ${JSON.stringify(usage.cells)}`);
    // 13: the closed monitoring period and its aggregates are preserved.
    const inspected = helper('--inspect');
    if (inspected.periods.length !== 1 || !inspected.periods[0].closed || inspected.aggregates_300s < 2 || JSON.stringify(inspected.aggregate_source_ids) !== '[9101]') throw new Error(`history ${JSON.stringify(inspected)}`);
    // Existing monitored devices keep reporting their own totals.
    const legacy = await page.evaluate(async () => (await fetch('/networking/ip-wan-monitor/traffic/device-usage?range=custom&start=2026-01-15T00:00:00&end=2026-01-15T23:59:00')).json());
    if (legacy.summary.download_bytes !== 1000 || legacy.summary.upload_bytes !== 300) throw new Error(`existing monitored totals changed ${JSON.stringify(legacy.summary)}`);
    evidence.doorbell = { seeded, inspected, finalRow: usage.cells };
  });
  await run('mobile-layout-focus-and-browser-quality', async () => {
    const mobile = await session(adminEmail, true);
    await assertPage(mobile, '/networking/ip-wan-monitor/traffic/devices', [/Device Usage/i], 'mobile device usage');
    await screenshot(mobile, 'device-usage-mobile');
    await mobile.keyboard.press('Tab');
    if (!await mobile.evaluate(() => Boolean(document.activeElement))) throw new Error('keyboard focus unavailable');
    await mobile.context().close();
  });
  await run('permission-boundaries', async () => {
    const viewer = await session(viewerEmail);
    const response = await viewer.goto(`${base}/infrastructure/asset-manager/9450`, { waitUntil: 'networkidle' });
    if (response.status() !== 200 || (await viewer.locator('[data-traffic-context-form]').count()) !== 0) throw new Error('viewer received mutation controls');
    const networkOnly = await session(fixture.network_only_email);
    const networkPage = await networkOnly.goto(`${base}/infrastructure/asset-manager/9401`, { waitUntil: 'networkidle' });
    if (![403, 404].includes(networkPage.status())) throw new Error(`network-only Asset Manager status ${networkPage.status()}`);
    const assetOnly = await session(fixture.asset_only_email);
    const dnsPage = await assetOnly.goto(`${base}/networking/dns-manager?tab=clients`, { waitUntil: 'networkidle' });
    if (![403, 404].includes(dnsPage.status())) throw new Error(`asset-only DNS status ${dnsPage.status()}`);
    const trafficPage = await assetOnly.goto(`${base}/networking/ip-wan-monitor/traffic/devices`, { waitUntil: 'networkidle' });
    if (![403, 404].includes(trafficPage.status())) throw new Error(`asset-only Network Traffic status ${trafficPage.status()}`);
    const dnsOnly = await session(fixture.dns_only_email);
    const assetFromDns = await dnsOnly.goto(`${base}/infrastructure/asset-manager/9401`, { waitUntil: 'networkidle' });
    if (![403, 404].includes(assetFromDns.status())) throw new Error(`dns-only Asset Manager status ${assetFromDns.status()}`);
    const trafficFromDns = await dnsOnly.goto(`${base}/networking/ip-wan-monitor/traffic/devices`, { waitUntil: 'networkidle' });
    if (![403, 404].includes(trafficFromDns.status())) throw new Error(`dns-only Network Traffic status ${trafficFromDns.status()}`);
    const viewerPost = await viewer.request.post(`${base}/infrastructure/asset-manager/9450/network-traffic`, { form: { enabled: '1', csrf_token: '' } });
    if (![400, 403, 422].includes(viewerPost.status())) throw new Error(`viewer mutation status ${viewerPost.status()}`);
  });
  await run('browser-console-and-page-errors', async () => {
    if (evidence.pageErrors.length) throw new Error(`page errors: ${evidence.pageErrors.join(' | ')}`);
    const unexpected = evidence.console.filter(message => !/\b(403|404)\b/.test(message));
    if (unexpected.length) throw new Error(`unexpected console errors: ${unexpected.join(' | ')}`);
  });
} finally {
  for (const context of contexts) await context.close().catch(() => {});
  await browser.close();
}

const sql = sqlCountFile ? JSON.parse(await fs.readFile(sqlCountFile, 'utf8')) : null;
const output = { fixture, results, evidence, sql, environment: { base, browser: 'chrome' } };
await fs.writeFile(`${artifacts}/stage2b-browser-results.json`, JSON.stringify(output, null, 2));
console.log(JSON.stringify(output));
if (results.some(item => item.status !== 'PASS')) process.exitCode = 1;
