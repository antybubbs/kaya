// Browser acceptance for VLAN/IP Manager quick ping result colours.
// Serves the repository's real stylesheets (in app/templates/base.html order), the real Managed Records
// action-cell and IP detail Ping markup, and the production app/static/js/ip_addresses.js in Chrome.
// Only POST /networking/vlan-ip-manager/{id}/ping is stubbed, using the JSON shape returned by
// app/routers/ip_addresses.py::ping_ip_address. Asserts computed colours, not class names.
// Usage: node scripts/quick_ping_browser_acceptance.mjs   (ARTIFACT_DIR to keep screenshots)
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const repo = process.env.KAYA_REPO_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const staticRoot = path.join(repo, 'app', 'static');
const artifacts = process.env.ARTIFACT_DIR || '';
if (artifacts) fs.mkdirSync(artifacts, { recursive: true });

const read = (file) => fs.readFileSync(path.join(repo, file), 'utf8');
const cssOrder = [...read('app/templates/base.html').matchAll(/<link rel="stylesheet" href="([^"]+)"/g)]
  .map((m) => m[1].replace(/\{\{ request\.url_for\('static', path='([^']+)'\) \}\}/, '/static/$1').replace(/\?v=.*$/, ''));
const actionCell = read('app/templates/ip_addresses.html').match(/<td class="action-col">.*?<\/td>/)[0];
const detailCard = read('app/templates/ip_address_detail.html').match(/<div class="service-card" data-ping-card>[\s\S]*?<\/button>\s*<\/div>/)[0]
  .replace(/\{\{ record\.id \}\}/g, '105').replace(/\{\{ csrf_token \}\}/g, 'fake-csrf');
const rows = [[101, '192.0.2.11'], [102, '192.0.2.12'], [103, '192.0.2.13'], [104, '192.0.2.14']];
const rowHtml = rows.map(([id, ip]) => `<tr><td class="select-col"><input class="row-select" type="checkbox" value="${id}"></td>`
  + actionCell.replace(/\{\{ row\.id \}\}/g, id).replace(/\{\{ row\.address \}\}/g, ip).replace(/\{\{ csrf_token \}\}/g, 'fake-csrf')
  + `<td class="mono">${ip}</td></tr>`).join('');
const pageHtml = (theme) => `<!doctype html><html lang="en"${theme ? ` data-kaya-theme="${theme}"` : ''}><head><meta charset="utf-8">
${cssOrder.map((href) => `<link rel="stylesheet" href="${href}">`).join('')}</head><body><main class="content">
<section class="panel"><form data-ip-bulk-form><table><tbody>${rowHtml}</tbody></table></form></section>
<section class="panel" id="detail">${detailCard}</section></main><script src="/static/js/ip_addresses.js" defer></script></body></html>`;

const checkedAt = '2026-01-01T00:00:00Z';
const result = (id, target, ok, status, latency, reason) => [200, { record_id: id, target, ok, status, latency_ms: latency, reason, error: reason, checked_at: checkedAt }];
const responses = {
  101: result(101, '192.0.2.11', true, 'success', 12.5, null),
  102: result(102, '192.0.2.12', false, 'no_response', null, 'Timed out'),
  103: result(103, '192.0.2.13', false, 'error', null, 'Ping command is not installed in the container.'),
  104: [429, { detail: 'Too many manual ping requests. Try again shortly.' }],
  105: result(105, '192.0.2.15', true, 'success', 3.1, null),
};
let overrides = {};
let requests = [];
let theme = '';

const types = { '.css': 'text/css', '.js': 'text/javascript', '.woff2': 'font/woff2', '.svg': 'image/svg+xml', '.png': 'image/png' };
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://acceptance.invalid');
  const ping = url.pathname.match(/^\/networking\/vlan-ip-manager\/(\d+)\/ping$/);
  if (ping && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      const [code, json] = overrides[ping[1]] || responses[ping[1]];
      requests.push({ id: Number(ping[1]), csrf: body.includes('fake-csrf') });
      setTimeout(() => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(json)); }, 500);
    });
    return;
  }
  if (url.pathname === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end(pageHtml(theme)); return; }
  const file = path.resolve(staticRoot, '.' + decodeURIComponent(url.pathname.replace(/^\/static/, '')));
  if (url.pathname.startsWith('/static/') && file.startsWith(staticRoot + path.sep) && fs.existsSync(file)) {
    res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream' });
    res.end(fs.readFileSync(file));
    return;
  }
  res.writeHead(404); res.end();
});

const failures = [];
const expect = (condition, message) => { if (!condition) failures.push(`[${theme || 'command'}] ${message}`); };
const parse = (value) => (value.match(/[\d.]+/g) || []).map(Number);
const hue = (value) => { const [r, g, b, a = 1] = parse(value); return { r, g, b, a }; };
const isGreen = (c) => c.a > 0 && c.g > c.r && c.g > c.b;
const isRed = (c) => c.a > 0 && c.r > c.g && c.r > c.b && c.g < c.r * 0.7;
const isAmber = (c) => c.a > 0 && c.r > c.b && c.g > c.b && c.g >= c.r * 0.45 && c.g <= c.r * 0.85;
const isNeutral = (c) => c.a === 0 || (Math.abs(c.r - c.g) < 20 && Math.abs(c.g - c.b) < 30);

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ channel: 'chrome', headless: true });
try {
  for (theme of ['', 'light-ops']) {
    overrides = {};
    requests = [];
    const page = await browser.newPage({ viewport: { width: 700, height: 420 } });
    const errors = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    await page.goto(base + '/', { waitUntil: 'networkidle' });
    const sel = (id) => `[data-ping-record-id="${id}"]`;
    const settle = async () => { await page.mouse.move(0, 0); await page.waitForTimeout(350); };
    const style = (selector) => page.$eval(selector, (el) => { const c = getComputedStyle(el); return { cls: el.className, disabled: el.disabled, bg: c.backgroundColor, border: c.borderTopColor, color: c.color }; });
    const shot = async (id, name) => { if (artifacts) await page.locator(sel(id)).screenshot({ path: path.join(artifacts, `${theme || 'command'}-${name}.png`) }); };
    const clickAndWait = async (id) => { await page.click(sel(id)); await page.waitForFunction((s) => !document.querySelector(s).disabled, sel(id)); await settle(); };

    for (const [id] of rows) { const s = await style(sel(id)); expect(isNeutral(hue(s.bg)) && isNeutral(hue(s.border)), `row ${id} should start neutral (${s.bg} / ${s.border})`); }
    await shot(101, '1-before');

    const geometry = (selector) => page.$eval(selector, (el) => {
      const rect = (node) => { const r = node.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, width: r.width, height: r.height }; };
      const icon = el.querySelector('.quick-ping-icon');
      const spinner = getComputedStyle(icon, '::after');
      return { button: rect(el), icon: rect(icon), label: rect(el.querySelector('.quick-ping-label')), spinnerContent: spinner.content, spinnerWidth: parseFloat(spinner.width), spinnerAnimation: spinner.animationName };
    });
    const idleGeometry = await geometry(sel(101));
    await page.click(sel(101));
    await settle();
    const loading = await style(sel(101));
    expect(loading.disabled && loading.cls.includes('is-loading'), 'row 101 should be disabled and loading while checking');
    expect(isNeutral(hue(loading.bg)), `loading should be neutral (${loading.bg})`);
    const loadingGeometry = await geometry(sel(101));
    const spinnerLeft = loadingGeometry.icon.left + loadingGeometry.icon.width / 2 - loadingGeometry.spinnerWidth / 2;
    const spinnerRight = spinnerLeft + loadingGeometry.spinnerWidth;
    expect(loadingGeometry.spinnerContent === '""' && loadingGeometry.spinnerAnimation === 'quick-ping-spin', `spinner should render in the icon slot (${JSON.stringify(loadingGeometry)})`);
    expect(spinnerRight <= loadingGeometry.label.left && loadingGeometry.icon.right <= loadingGeometry.label.left, `spinner (${spinnerLeft.toFixed(1)}-${spinnerRight.toFixed(1)}) must not overlap label (${loadingGeometry.label.left.toFixed(1)})`);
    expect(spinnerLeft >= loadingGeometry.button.left, 'spinner should stay inside the button');
    expect(Math.abs(loadingGeometry.button.width - idleGeometry.button.width) < 0.5 && Math.abs(loadingGeometry.button.height - idleGeometry.button.height) < 0.5, `button size should not change while loading (${idleGeometry.button.width}x${idleGeometry.button.height} -> ${loadingGeometry.button.width}x${loadingGeometry.button.height})`);
    expect(Math.abs(loadingGeometry.label.left - idleGeometry.label.left) < 0.5, 'label should not shift while loading');
    await shot(101, '2-loading');
    await page.waitForFunction((s) => !document.querySelector(s).disabled, sel(101));
    await settle();
    let s = await style(sel(101));
    expect(isGreen(hue(s.bg)) && isGreen(hue(s.border)), `success should be green (${s.bg} / ${s.border})`);
    await shot(101, '3-green');
    const untouched = await style(sel(102));
    expect(isNeutral(hue(untouched.bg)) && !/quick-ping-/.test(untouched.cls.replace('quick-ping-button', '')), 'row 102 should be unaffected by row 101');

    await clickAndWait(102);
    s = await style(sel(102));
    expect(isRed(hue(s.bg)) && isRed(hue(s.border)), `no response should be red (${s.bg} / ${s.border})`);
    await shot(102, '4-red');
    await clickAndWait(103);
    s = await style(sel(103));
    expect(isAmber(hue(s.bg)) && isAmber(hue(s.border)), `execution error should be amber (${s.bg} / ${s.border})`);
    await shot(103, '5-amber');
    await clickAndWait(104);
    s = await style(sel(104));
    expect(isAmber(hue(s.bg)), `HTTP error should be amber (${s.bg})`);

    await page.waitForTimeout(800);
    await page.hover(sel(101));
    await page.waitForTimeout(350);
    s = await style(sel(101));
    expect(isGreen(hue(s.bg)), `success should persist after loading and on hover (${s.bg})`);

    overrides = { 101: result(101, '192.0.2.11', false, 'no_response', null, 'Timed out') };
    await page.click(sel(101));
    await settle();
    s = await style(sel(101));
    expect(!s.cls.includes('quick-ping-success') && isNeutral(hue(s.bg)), `second click should reset to neutral loading (${s.cls})`);
    await page.waitForFunction((q) => !document.querySelector(q).disabled, sel(101));
    await settle();
    s = await style(sel(101));
    expect(isRed(hue(s.bg)), `second click result should be red (${s.bg})`);
    expect((await style(sel(102))).cls.includes('quick-ping-no-response') && (await style(sel(103))).cls.includes('quick-ping-error'), 'other rows keep their own results');

    const perRow = requests.reduce((acc, r) => ({ ...acc, [r.id]: (acc[r.id] || 0) + 1 }), {});
    expect(JSON.stringify(perRow) === JSON.stringify({ 101: 2, 102: 1, 103: 1, 104: 1 }), `expected one request per click, got ${JSON.stringify(perRow)}`);
    expect(requests.every((r) => r.csrf), 'every ping request should carry the CSRF token');

    const detail = '#detail [data-ping-url]';
    const detailState = () => page.$eval(detail, (el) => { const card = el.closest('[data-ping-card]'); const b = getComputedStyle(el); const c = getComputedStyle(card); return {
      text: el.textContent, card: card.className, message: card.querySelector('[data-ping-message]').textContent,
      bg: b.backgroundColor, border: b.borderTopColor, color: b.color, cardBorder: c.borderTopColor, cardShadow: c.boxShadow }; });
    const detailIdle = await detailState();
    expect(isNeutral(hue(detailIdle.bg)), `detail Ping should start neutral (${detailIdle.bg})`);
    const detailRun = async (response, text) => {
      overrides = { 105: response };
      await page.waitForFunction((q) => !document.querySelector(q).disabled, detail);
      await page.click(detail);
      expect((await detailState()).text === 'Pinging...', 'detail Ping should show Pinging... while checking');
      await page.waitForFunction(([q, t]) => document.querySelector(q).textContent === t, [detail, text]);
      await settle();
      return detailState();
    };
    let d = await detailRun(responses[105], 'Up - 3.1ms');
    expect(d.card.includes('ping-up') && d.message === 'Device responded successfully.', `detail Ping should report Up (${JSON.stringify(d)})`);
    expect(isGreen(hue(d.bg)) && isGreen(hue(d.border)), `detail Up should be green (${d.bg} / ${d.border})`);
    console.log(`[${theme || 'command'}] detail up: button ${d.bg} / ${d.border} / ${d.color}; card ${d.cardBorder} / ${d.cardShadow}`);
    if (artifacts) await page.locator('#detail [data-ping-card]').screenshot({ path: path.join(artifacts, `${theme || 'command'}-6-detail-up.png`) });
    d = await detailRun(result(105, '192.0.2.15', false, 'no_response', null, 'Timed out'), 'Down');
    expect(d.card.includes('ping-down') && !d.card.includes('ping-up') && d.message === 'Timed out', `detail Ping should report Down (${JSON.stringify(d)})`);
    expect(isRed(hue(d.bg)) && isRed(hue(d.border)), `detail Down should be red (${d.bg} / ${d.border})`);
    console.log(`[${theme || 'command'}] detail down: button ${d.bg} / ${d.border} / ${d.color}; card ${d.cardBorder} / ${d.cardShadow}`);
    if (artifacts) await page.locator('#detail [data-ping-card]').screenshot({ path: path.join(artifacts, `${theme || 'command'}-7-detail-down.png`) });
    d = await detailRun([429, { detail: 'Too many manual ping requests. Try again shortly.' }], 'Error');
    expect(d.card.includes('ping-down') && d.message === 'Too many manual ping requests. Try again shortly.' && isRed(hue(d.bg)), `detail Error should be red with message (${JSON.stringify(d)})`);
    // Existing behaviour: after an error the button re-enables and restores the text shown before the click.
    await page.waitForFunction((q) => !document.querySelector(q).disabled && document.querySelector(q).textContent === 'Down', detail);
    expect(errors.length === 0, `page errors: ${errors.join('; ')}`);
    await page.close();
  }
} finally {
  await browser.close();
  server.close();
}

if (failures.length) {
  console.error(`Quick ping browser acceptance FAILED:\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log('Quick ping browser acceptance passed (command and light-ops themes).');
