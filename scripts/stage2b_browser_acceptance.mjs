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
    // The fixture's January rows are optional tracked-device history, which the
    // Overview's tracked list reports; Device Usage reads automatic observed usage
    // and must not repeat or invent it for that window.
    if (custom.summary.download_bytes !== 0 || custom.summary.measured_endpoints !== 0) throw new Error(`unexpected observed totals ${JSON.stringify(custom.summary)}`);
    const tracked = await admin.evaluate(async () => (await fetch('/networking/ip-wan-monitor/traffic/report?range=custom&start=2026-01-15T00:00&end=2026-01-15T23:59')).json());
    const trackedTotals = tracked.devices.devices.reduce((sum, row) => [sum[0] + (row.download_bytes || 0), sum[1] + (row.upload_bytes || 0)], [0, 0]);
    if (trackedTotals[0] !== 1000 || trackedTotals[1] !== 300) throw new Error(`tracked-device totals ${JSON.stringify(trackedTotals)}`);
    if (custom.page_count < 1 || custom.page_size < 1) throw new Error('pagination metadata missing');
    // A configured local network makes automatic accounting ready; the notice stays hidden.
    if (!custom.summary.accounting || custom.summary.accounting.ready !== true) throw new Error(`accounting readiness ${JSON.stringify(custom.summary.accounting)}`);
    if (!(await admin.locator('[data-device-usage-accounting-notice]').isHidden())) throw new Error('accounting notice shown while ready');
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
    if (!(await page.locator('body').innerText()).match(/Device tracking\s+Disabled/i)) throw new Error('context confirmation enabled device tracking');
    const noCsrf = await page.request.post(`${base}/infrastructure/asset-manager/9450/network-traffic`, { form: { enabled: '1', csrf_token: '' } });
    if (![400, 403, 422].includes(noCsrf.status())) throw new Error(`CSRF status ${noCsrf.status()}`);
    const enable = page.locator('form[action$="/network-traffic"]');
    const enabledResponse = await Promise.all([page.waitForResponse(response => response.url().endsWith('/network-traffic')), enable.getByRole('button', { name: /Start device tracking/i }).click()]);
    if (enabledResponse[0].status() !== 303) throw new Error(`enable status ${enabledResponse[0].status()}`);
    await page.waitForLoadState('networkidle');
    if (!(await page.locator('body').innerText()).match(/Active|Awaiting data/i)) throw new Error('enabled state missing');
    const disable = page.locator('form[action$="/network-traffic"]');
    await disable.getByRole('button', { name: /Stop device tracking/i }).click();
    await page.waitForLoadState('networkidle');
    if (!(await page.locator('body').innerText()).match(/Disabled/i)) throw new Error('disabled state missing');
  });
  await run('doorbell-monitoring-consistency', async () => {
    // Ring-doorbell-style device: DHCP identity, source-less adoption assignment
    // and an administrator-confirmed Cisco context for the same address. Usage
    // is recorded automatically; device tracking is optional and separate.
    const page = admin;
    const address = '192.0.2.115';
    const doorbellUrl = '/infrastructure/asset-manager/9460';
    const helper = mode => JSON.parse(execFileSync(process.env.KAYA_STAGE2B_PYTHON, ['scripts/stage2b_seed_doorbell_flows.py', ...(mode ? [mode] : [])], { encoding: 'utf8' }).trim().split('\n').at(-1));
    // The fixture's site timezone is UTC, so the custom range is entered in UTC.
    const utcNow = () => new Date().toISOString().slice(0, 16);
    const usageRows = async () => {
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
      const count = await rows.count();
      const parsed = [];
      for (let index = 0; index < count; index += 1) {
        const cells = (await rows.nth(index).locator('th, td').allInnerTexts()).map(text => text.replace(/\s+/g, ' ').trim());
        parsed.push({ row: rows.nth(index), cells, identity: cells[1], vlan: cells[2], source: cells[3], download: cells[4], upload: cells[5], observed: cells[8] });
      }
      return parsed;
    };
    const ciscoRow = async () => {
      const rows = (await usageRows()).filter(item => item.source.includes('Stage2B Cisco exporter'));
      if (rows.length !== 1) throw new Error(`expected one Cisco-context row for ${address}, found ${rows.length}`);
      return rows[0];
    };
    const profileBody = async () => { await page.goto(`${base}${doorbellUrl}`, { waitUntil: 'networkidle' }); return (await page.locator('#asset-traffic').innerText()).replace(/\s+/g, ' '); };
    const api = async () => page.evaluate(async query => (await fetch(`/networking/ip-wan-monitor/traffic/device-usage?${query}`)).json(), `range=24h&q=${address}`);

    // 1-3: recognised and linked to its asset; observed without byte data yet.
    let usage = await ciscoRow();
    if (!usage.identity.includes('Stage2B Doorbell')) throw new Error(`identity cell: ${usage.identity}`);
    if (usage.download !== 'Traffic observed — usage unavailable' || /Not monitored/i.test(usage.cells.join(' '))) throw new Error(`initial state: ${JSON.stringify(usage.cells)}`);
    if (!/^\d+%$/.test(usage.observed)) throw new Error(`observed share cell: ${usage.observed}`);
    // The confirmed assignment's VLAN is shown, as in Asset Profile.
    if (!usage.vlan.includes('Stage2B LAN A')) throw new Error(`VLAN cell: ${usage.vlan}`);
    // 4: the identity link opens the permanent asset record.
    await Promise.all([page.waitForURL(`**${doorbellUrl}`), usage.row.getByRole('link', { name: 'Stage2B Doorbell' }).click()]);
    // 5: confirmed assignment, optional tracking off and described as optional.
    const assetBody = await page.locator('body').innerText();
    if (!assetBody.includes(address)) throw new Error('assignment address missing from Asset Profile');
    if (!/Device tracking\s+Disabled/i.test(assetBody)) throw new Error('doorbell tracking was not disabled before the journey');
    if (!/recorded automatically/i.test(assetBody) || /must enable monitoring/i.test(assetBody)) throw new Error('Asset Profile still implies tracking is needed to see usage');
    // 6: start optional tracking explicitly (CSRF-protected form).
    const enabled = await Promise.all([
      page.waitForResponse(response => response.url().endsWith('/9460/network-traffic')),
      page.locator('form[action$="/network-traffic"]').getByRole('button', { name: /Start device tracking/i }).click(),
    ]);
    if (enabled[0].status() !== 303) throw new Error(`enable status ${enabled[0].status()}`);
    // 7: both screens agree on the tracking lifecycle.
    if (!/Device tracking Awaiting Data/i.test(await profileBody())) throw new Error('Asset Profile is not awaiting data after enabling');
    usage = await ciscoRow();
    if (!usage.identity.includes('Device tracking — awaiting data')) throw new Error(`Device Usage after enabling: ${JSON.stringify(usage.cells)}`);
    // 8: synthetic NSEL flows through the real collector path.
    const seeded = helper();
    if (seeded.tracked['9101:download'] !== seeded.expected_download || seeded.tracked['9101:upload'] !== seeded.expected_upload || seeded.tracked['9102:download'] !== undefined) throw new Error(`tracked usage ${JSON.stringify(seeded)}`);
    if (seeded.observed['9101:download'] !== seeded.expected_download || seeded.observed['9102:download'] !== seeded.other_source) throw new Error(`observed usage ${JSON.stringify(seeded)}`);
    // 9-10: measured usage in both reporting paths, never combined across sources.
    usage = await ciscoRow();
    if (!usage.identity.includes('Device tracking on')) throw new Error(`Device Usage after flows: ${JSON.stringify(usage.cells)}`);
    const measured = (await api()).devices.filter(row => row.address === address && row.source_context.includes('Stage2B Cisco exporter'));
    if (measured.length !== 1 || measured[0].download_bytes !== seeded.expected_download || measured[0].upload_bytes !== seeded.expected_upload) throw new Error(`Device Usage totals ${JSON.stringify(measured)}`);
    const otherRows = (await usageRows()).filter(item => item.source.includes('Stage2B NetFlow exporter'));
    if (otherRows.length !== 1 || !otherRows[0].source.includes('Separate source observation')) throw new Error(`second source row: ${JSON.stringify(otherRows.map(item => item.cells))}`);
    const profile = await profileBody();
    if (!/Device tracking Active/i.test(profile)) throw new Error(`Asset Profile status after flows: ${profile.slice(0, 200)}`);
    // The source-less adoption assignment covers both sources: per-source totals, no sum.
    if (!profile.includes(`Download ${seeded.expected_download} bytes · Upload ${seeded.expected_upload} bytes`) || !profile.includes(`Download ${seeded.other_source} bytes`)) throw new Error(`Asset Profile totals: ${profile}`);
    await screenshot(page, 'doorbell-asset-profile-measured');
    // 11-12: stop tracking; usage stays visible because it never depended on tracking.
    await page.locator('form[action$="/network-traffic"]').getByRole('button', { name: /Stop device tracking/i }).click();
    await page.waitForLoadState('networkidle');
    if (!/Device tracking Disabled/i.test(await profileBody())) throw new Error('Asset Profile not disabled');
    usage = await ciscoRow();
    if (/Device tracking/i.test(usage.identity) || usage.download === 'Traffic observed — usage unavailable') throw new Error(`Device Usage after disabling: ${JSON.stringify(usage.cells)}`);
    // 13: the closed tracking period and its aggregates are preserved.
    const inspected = helper('--inspect');
    if (inspected.periods.length !== 1 || !inspected.periods[0].closed || inspected.aggregates_300s < 2 || JSON.stringify(inspected.aggregate_source_ids) !== '[9101]') throw new Error(`history ${JSON.stringify(inspected)}`);
    // Existing tracked devices keep reporting their own totals in the Overview list.
    const legacy = await page.evaluate(async () => (await fetch('/networking/ip-wan-monitor/traffic/report?range=custom&start=2026-01-15T00:00&end=2026-01-15T23:59')).json());
    const legacyDownload = legacy.devices.devices.reduce((sum, row) => sum + (row.download_bytes || 0), 0);
    const legacyUpload = legacy.devices.devices.reduce((sum, row) => sum + (row.upload_bytes || 0), 0);
    if (legacyDownload !== 1000 || legacyUpload !== 300) throw new Error(`existing tracked totals changed ${JSON.stringify(legacy.devices)}`);
    evidence.doorbell = { seeded, inspected, finalRow: usage.cells };
  });
  await run('automatic-observed-ip-usage-adoption-and-dhcp', async () => {
    // Journey: unknown IP usage appears automatically; explicit adoption links
    // identity without moving history; a DHCP change keeps ownership bounded.
    const page = admin;
    const seeded = JSON.parse(execFileSync(process.env.KAYA_STAGE2B_PYTHON, ['scripts/stage2b_seed_endpoint_flows.py'], { encoding: 'utf8' }).trim().split('\n').at(-1));
    const inspect = () => JSON.parse(execFileSync(process.env.KAYA_STAGE2B_PYTHON, ['scripts/stage2b_seed_endpoint_flows.py', '--inspect'], { encoding: 'utf8' }).trim().split('\n').at(-1));
    const usage = async (address, range = '24h') => (await page.evaluate(async query => (await fetch(`/networking/ip-wan-monitor/traffic/device-usage?${query}`)).json(), `range=${range}&q=${encodeURIComponent(address)}`)).devices.filter(row => row.address === address);
    const profile = async (assetId) => { await page.goto(`${base}/infrastructure/asset-manager/${assetId}`, { waitUntil: 'networkidle' }); return (await page.locator('#asset-traffic').innerText()).replace(/\s+/g, ' '); };
    const confirm = async (assetId, assignmentId) => {
      await page.goto(`${base}/infrastructure/asset-manager/${assetId}`, { waitUntil: 'networkidle' });
      const form = page.locator(`form[action$="/network-assignment/${assignmentId}/confirm"]`);
      // Another scenario may have left a one-shot dialog handler registered.
      page.once('dialog', dialog => dialog.accept().catch(() => {}));
      const [response] = await Promise.all([page.waitForResponse(item => item.url().includes(`/network-assignment/${assignmentId}/confirm`)), form.getByRole('button', { name: /Confirm/i }).click()]);
      if (![200, 303].includes(response.status())) throw new Error(`confirm status ${response.status()}`);
      await page.waitForLoadState('networkidle');
    };
    // 1-4: an unknown IP shows measured bytes with no manual activation and no records created.
    const unknown = await usage(seeded.addresses.unknown);
    if (unknown.length !== 1 || unknown[0].download_bytes !== seeded.expected.unknown.download || unknown[0].upload_bytes !== seeded.expected.unknown.upload || unknown[0].identity_status !== 'unidentified') throw new Error(`unknown endpoint ${JSON.stringify(unknown)}`);
    await page.goto(`${base}/networking/ip-wan-monitor/traffic/devices`, { waitUntil: 'networkidle' });
    await page.locator('[data-device-usage-search]').fill(seeded.addresses.unknown);
    await page.locator('[data-device-usage-search]').dispatchEvent('input');
    await page.waitForLoadState('networkidle');
    const unknownRow = page.locator('.device-usage-table tbody tr').filter({ hasText: seeded.addresses.unknown });
    await unknownRow.first().waitFor();
    const unknownCells = (await unknownRow.first().locator('th, td').allInnerTexts()).map(text => text.replace(/\s+/g, ' ').trim());
    if (/Not monitored|usage unavailable/i.test(unknownCells.join(' ')) || !/Unidentified/.test(unknownCells[1])) throw new Error(`unknown endpoint cells ${JSON.stringify(unknownCells)}`);
    let sideEffects = inspect();
    if (sideEffects.managed_ips !== 0 || sideEffects.monitoring_records !== 0) throw new Error(`automatic records created ${JSON.stringify(sideEffects)}`);
    // 5-7: a pending proposal does not confirm identity; explicit confirmation does,
    // without changing the IP's usage, and the profile shows only its interval.
    let adopt = await usage(seeded.addresses.adopt);
    if (adopt.length !== 1 || adopt[0].identity_status === 'confirmed') throw new Error(`pending proposal confirmed identity ${JSON.stringify(adopt)}`);
    await confirm(seeded.assets.adopt, seeded.pending.adopt);
    adopt = await usage(seeded.addresses.adopt);
    if (adopt.length !== 1 || adopt[0].asset_name !== 'Stage2B Adopted Camera' || adopt[0].download_bytes !== seeded.expected.adopt_usage.download || adopt[0].upload_bytes !== seeded.expected.adopt_usage.upload) throw new Error(`adopted endpoint ${JSON.stringify(adopt)}`);
    const adoptedProfile = await profile(seeded.assets.adopt);
    if (!adoptedProfile.includes(`Download ${seeded.expected.adopt_profile.download} bytes`) || !adoptedProfile.includes(`Upload ${seeded.expected.adopt_profile.upload} bytes`)) throw new Error(`adopted profile ${adoptedProfile}`);
    // 8-10: DHCP renewal confirmed; each owner keeps only its own interval.
    await confirm(seeded.assets.mover, seeded.pending.renewal);
    const mover = await profile(seeded.assets.mover);
    if (!mover.includes(`Download ${seeded.expected.mover_profile.download} bytes`) || !mover.includes(`Upload ${seeded.expected.mover_profile.upload} bytes`)) throw new Error(`DHCP mover profile ${mover}`);
    const reuser = await profile(seeded.assets.reuser);
    if (!reuser.includes(`Download ${seeded.expected.reuser_profile.download} bytes`) || !reuser.includes(`Upload ${seeded.expected.reuser_profile.upload} bytes`)) throw new Error(`reuser profile ${reuser}`);
    const newAddress = await usage(seeded.addresses.new);
    if (newAddress.length !== 1 || newAddress[0].download_bytes !== 66) throw new Error(`new DHCP address ${JSON.stringify(newAddress)}`);
    const oldAddress = await usage(seeded.addresses.old);
    if (oldAddress.length !== 1 || oldAddress[0].download_bytes !== seeded.expected.old_usage.download || oldAddress[0].asset_name !== 'Stage2B Address Reuser' || oldAddress[0].identity_whole_period !== false) throw new Error(`reused address ${JSON.stringify(oldAddress)}`);
    // 11/14: every range reports the same usage once, and custom ranges work.
    for (const range of ['7d', '30d', '90d']) {
      const rows = await usage(seeded.addresses.unknown, range);
      if (rows.length !== 1 || rows[0].download_bytes !== seeded.expected.unknown.download) throw new Error(`${range} unknown endpoint ${JSON.stringify(rows)}`);
    }
    const end = new Date().toISOString().slice(0, 16);
    const start = new Date(Date.now() - 6 * 3600 * 1000).toISOString().slice(0, 16);
    const custom = (await page.evaluate(async query => (await fetch(`/networking/ip-wan-monitor/traffic/device-usage?${query}`)).json(), `range=custom&start=${start}&end=${end}&q=${seeded.addresses.unknown}`)).devices;
    if (custom.length !== 1 || custom[0].download_bytes !== seeded.expected.unknown.download) throw new Error(`custom range ${JSON.stringify(custom)}`);
    sideEffects = inspect();
    if (sideEffects.managed_ips !== 0 || sideEffects.monitoring_records !== 0) throw new Error(`records created during adoption ${JSON.stringify(sideEffects)}`);
    await screenshot(page, 'automatic-observed-ip-usage');
    evidence.automatic = { seeded: seeded.expected, sideEffects };
  });
  await run('wan-selected-period-transfer-totals', async () => {
    // Journey D: WAN transfer totals follow the History Range and WAN source,
    // computed from seeded SNMP counter history; live throughput stays live.
    const page = admin;
    const seeded = JSON.parse(execFileSync(process.env.KAYA_STAGE2B_PYTHON, ['scripts/stage2b_seed_wan_history.py'], { encoding: 'utf8' }).trim().split('\n').at(-1));
    const formatBytes = (value) => { const units = ['B', 'KB', 'MB', 'GB', 'TB']; let number = Number(value); let index = 0; while (number >= 1024 && index < units.length - 1) { number /= 1024; index += 1; } return `${number.toFixed(number >= 100 || index === 0 ? 0 : 1)} ${units[index]}`; };
    const reports = [];
    page.on('request', request => { if (request.url().includes('/traffic/report')) reports.push(request.url()); });
    await page.goto(`${base}/networking/ip-wan-monitor/traffic`, { waitUntil: 'networkidle' });
    const cards = async () => ({
      download: (await page.locator('[data-summary="download_bytes_period"]').innerText()).trim(),
      upload: (await page.locator('[data-summary="upload_bytes_period"]').innerText()).trim(),
      downloadQuality: (await page.locator('[data-summary-quality="download_bytes_period"]').innerText()).trim(),
      label: (await page.locator('[data-period-label]').first().innerText()).trim(),
      live: (await page.locator('[data-summary="download_bps"]').innerText()).trim(),
    });
    const select = async (selector, value) => {
      const [response] = await Promise.all([page.waitForResponse(response => response.url().includes('/traffic/report')), page.locator(selector).selectOption(value)]);
      if (response.status() !== 200) throw new Error(`report status ${response.status()} for ${value}`);
      const body = await response.json();
      await page.waitForLoadState('networkidle');
      return body.wan.summary;
    };
    const checked = {};
    for (const [range, label] of [['24h', '24 hours'], ['7d', '7 days'], ['30d', '30 days'], ['90d', '90 days']]) {
      const summary = await select('[data-traffic-range]', range);
      const want = seeded.ranges[range].all;
      if (summary.download_bytes_period !== want.download || summary.upload_bytes_period !== want.upload) throw new Error(`${range} totals ${JSON.stringify(summary.period)} expected ${JSON.stringify(want)}`);
      const shown = await cards();
      if (shown.download !== formatBytes(want.download) || shown.upload !== formatBytes(want.upload)) throw new Error(`${range} cards ${JSON.stringify(shown)}`);
      if (!shown.label.includes(label)) throw new Error(`${range} card label ${shown.label}`);
      if (!/coverage/i.test(shown.downloadQuality)) throw new Error(`${range} coverage text ${shown.downloadQuality}`);
      if (shown.live === 'No data') throw new Error('live throughput card lost its value');
      checked[range] = { download: summary.download_bytes_period, coverage: summary.period.coverage };
    }
    // 24h has twelve 5-minute buckets without a counter delta on one interface.
    await select('[data-traffic-range]', '24h');
    if (!/partial/i.test((await cards()).downloadQuality)) throw new Error('missing counter buckets were not reported as partial coverage');
    // WAN source filter.
    await page.waitForFunction(id => [...document.querySelectorAll('[data-traffic-source] option')].some(option => option.value === String(id)), seeded.sources.b);
    const backup = await select('[data-traffic-source]', String(seeded.sources.b));
    if (backup.download_bytes_period !== seeded.ranges['24h'].b.download) throw new Error(`source filter ${JSON.stringify(backup.period)}`);
    if ((await cards()).download !== formatBytes(seeded.ranges['24h'].b.download)) throw new Error('source-filtered card did not update');
    await select('[data-traffic-source]', '');
    // Custom range: choosing Custom alone, or only a start, sends no request.
    const before = reports.length;
    await page.locator('[data-traffic-range]').selectOption('custom');
    await page.locator('[data-traffic-start]').fill(seeded.custom.start);
    await page.locator('[data-traffic-start]').dispatchEvent('change');
    await page.waitForTimeout(300);
    if (reports.length !== before) throw new Error('an incomplete custom range was requested');
    await page.locator('[data-traffic-end]').fill(seeded.custom.end);
    const [customResponse] = await Promise.all([page.waitForResponse(response => response.url().includes('/traffic/report') && response.url().includes('range=custom')), page.locator('[data-traffic-end]').dispatchEvent('change')]);
    const custom = (await customResponse.json()).wan.summary;
    if (custom.download_bytes_period !== seeded.custom.all.download || custom.upload_bytes_period !== seeded.custom.all.upload || custom.period.bucket_seconds !== 3600) throw new Error(`custom totals ${JSON.stringify(custom.period)} expected ${JSON.stringify(seeded.custom.all)}`);
    await page.waitForLoadState('networkidle');
    if ((await cards()).download !== formatBytes(seeded.custom.all.download)) throw new Error('custom card did not update');
    await screenshot(page, 'wan-selected-period-totals');
    evidence.wan = { checked, custom: custom.period, backup: backup.period };
  });
  await run('local-network-settings-and-accounting-notice', async () => {
    // Settings manages the local networks that make endpoints eligible for automatic
    // accounting; Device Usage explains when nothing can be recorded.
    const page = admin;
    const settingsUrl = `${base}/networking/ip-wan-monitor/traffic/settings`;
    const rowFor = cidr => page.locator('[data-local-network-rows] tr').filter({ hasText: cidr });
    const waitStatus = async pattern => page.waitForFunction(source => new RegExp(source, 'i').test(document.querySelector('[data-local-network-status]')?.textContent || ''), pattern.source);
    await page.goto(settingsUrl, { waitUntil: 'networkidle' });
    await rowFor('192.0.2.0/24').waitFor();
    if (!/eligible for automatic per-IP traffic accounting/i.test(await page.locator('#traffic-local-networks').innerText())) throw new Error('local network purpose not explained');
    // Invalid input is rejected server-side and nothing is added. The browser logs
    // that one deliberate 400; it is verified and then excluded from the console check.
    const form = page.locator('[data-local-network-form]');
    const consoleBefore = evidence.console.length;
    await form.locator('[name="name"]').fill('Bad range');
    await form.locator('[name="network_cidr"]').fill('192.0.2.0/33');
    await form.getByRole('button', { name: /Add local network/i }).click();
    await waitStatus(/valid IPv4 or IPv6 CIDR/);
    for (let attempt = 0; attempt < 20 && evidence.console.length === consoleBefore; attempt += 1) await page.waitForTimeout(100);
    const expected = evidence.console.splice(consoleBefore);
    if (expected.length !== 1 || !/400/.test(expected[0])) throw new Error(`unexpected console output for invalid CIDR: ${JSON.stringify(expected)}`);
    if (await rowFor('192.0.2.0/33').count() !== 0) throw new Error('invalid network listed');
    // Add, rename, disable/enable and remove a synthetic range.
    await form.locator('[name="name"]').fill('Stage2B lab');
    await form.locator('[name="network_cidr"]').fill('203.0.113.9/24');
    await form.getByRole('button', { name: /Add local network/i }).click();
    await waitStatus(/Local network added/);
    const lab = rowFor('203.0.113.0/24');
    await lab.waitFor();
    await lab.locator('[data-local-network-name]').fill('Stage2B lab renamed');
    await lab.getByRole('button', { name: /Save name/i }).click();
    await waitStatus(/name saved/);
    if (await rowFor('203.0.113.0/24').locator('[data-local-network-name]').inputValue() !== 'Stage2B lab renamed') throw new Error('rename not shown');
    // With the only accounting LAN disabled, Device Usage says nothing can be recorded.
    await rowFor('192.0.2.0/24').getByRole('button', { name: /^Disable$/ }).click();
    await waitStatus(/disabled/);
    await rowFor('203.0.113.0/24').getByRole('button', { name: /^Disable$/ }).click();
    await waitStatus(/disabled/);
    await page.goto(`${base}/networking/ip-wan-monitor/traffic/devices`, { waitUntil: 'networkidle' });
    const notice = page.locator('[data-device-usage-accounting-notice]');
    await notice.waitFor({ state: 'visible' });
    if (!/not being recorded/i.test(await notice.innerText())) throw new Error(`notice text ${await notice.innerText()}`);
    await Promise.all([page.waitForURL('**/traffic/settings#traffic-local-networks'), notice.getByRole('link', { name: /Configure in Network Traffic Settings/i }).click()]);
    await rowFor('192.0.2.0/24').waitFor();
    await rowFor('192.0.2.0/24').getByRole('button', { name: /^Enable$/ }).click();
    await waitStatus(/enabled/);
    page.once('dialog', dialog => dialog.accept().catch(() => {}));
    await rowFor('203.0.113.0/24').getByRole('button', { name: /Remove/i }).click();
    await waitStatus(/removed/);
    if (await rowFor('203.0.113.0/24').count() !== 0) throw new Error('removed network still listed');
    await page.goto(`${base}/networking/ip-wan-monitor/traffic/devices`, { waitUntil: 'networkidle' });
    if (!(await page.locator('[data-device-usage-accounting-notice]').isHidden())) throw new Error('notice still shown after re-enabling');
    await screenshot(page, 'local-network-settings');
    // Read-only users see the list but no controls; the server rejects their changes.
    const viewer = await session(viewerEmail);
    await viewer.goto(settingsUrl, { waitUntil: 'domcontentloaded' });
    await viewer.locator('[data-local-network-rows] tr').filter({ hasText: '192.0.2.0/24' }).waitFor();
    if (await viewer.locator('[data-local-network-form]').count() !== 0 || await viewer.locator('[data-local-network-rows] button').count() !== 0) throw new Error('read-only user sees local network controls');
    const denied = await viewer.request.post(`${base}/networking/ip-wan-monitor/traffic/local-networks`, { data: { name: 'Viewer attempt', network_cidr: '198.18.0.0/15' } });
    if (![400, 403].includes(denied.status())) throw new Error(`viewer create status ${denied.status()}`);
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
