#!/usr/bin/env node
// Cookie / tracker audit (phase 7), driven by Playwright + Chromium.
//
// Loads a page three times in fresh browser contexts and records, at each
// stage, the cookies, localStorage/sessionStorage keys, and third-party
// requests that fired:
//   1. before_consent  - straight after load, no interaction
//   2. after_reject     - click a "reject" control, reload
//   3. after_accept     - click an "accept" control, reload
// Any non-essential cookie or third-party request in before_consent or
// after_reject is a consent violation (the caller turns it into an EXPLOITED
// tracking finding). Output is JSON on stdout and, with --out, to a file.
//
// Playwright is not resolvable from this file's directory; it lives in the
// skill's share dir. Pass that dir in RG_PLAYWRIGHT_BASE (…/node), and set
// PLAYWRIGHT_BROWSERS_PATH to …/node/ms-playwright, as check_tools/install do.
//
// Usage: node cookie_audit.mjs --url http://127.0.0.1:3105/ [--out audit.json]
//        [--reject-text Reject] [--accept-text Accept] [--timeout 15000]

import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
import process from 'node:process';

function arg(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && i + 1 < process.argv.length ? process.argv[i + 1] : def;
}

const url = arg('url');
if (!url) { console.error('cookie_audit: --url is required'); process.exit(2); }
const out = arg('out');
const rejectText = arg('reject-text', 'Reject');
const acceptText = arg('accept-text', 'Accept');
const timeout = parseInt(arg('timeout', '15000'), 10);

// Scope guard: only ever drive a loopback page unless explicitly allowed.
const allowNonLocal = process.env.RG_ALLOW_NONLOCAL === '1';
try {
  const h = new URL(url).hostname;
  const local = ['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0'].includes(h);
  if (!local && !allowNonLocal) {
    console.error(`cookie_audit: refusing non-loopback target ${h} (set RG_ALLOW_NONLOCAL=1 only for a confirmed, owned target)`);
    process.exit(2);
  }
} catch { console.error('cookie_audit: invalid --url'); process.exit(2); }

const base = process.env.RG_PLAYWRIGHT_BASE;
const require = createRequire(base ? `${base}/package.json` : import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch (e) {
  console.error('cookie_audit: cannot load playwright. Install it via tools.lock.yaml and set RG_PLAYWRIGHT_BASE. ' + e.message);
  process.exit(3);
}

const pageHost = new URL(url).host;
const ESSENTIAL = /^(session|sid|csrf|xsrf|__host-|__secure-|connect\.sid|sess)/i;
// Storing the user's own consent choice (including a rejection) is strictly
// necessary and must not count as a tracker.
const CONSENT_KEY = /^(consent|cookie[_-]?consent|cookieconsent|gdpr|ccpa|cmp|privacy|pref|prefs|preferences|banner)/i;

function isThirdParty(reqUrl) {
  try { return new URL(reqUrl).host !== pageHost && !reqUrl.startsWith('data:'); }
  catch { return false; }
}

async function stage(browser, { reject = false, accept = false } = {}) {
  const context = await browser.newContext();
  const thirdParty = [];
  context.on('request', (req) => { if (isThirdParty(req.url())) thirdParty.push({ url: req.url(), method: req.method() }); });
  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'networkidle', timeout }).catch(() => {});

  async function clickByText(text) {
    for (const sel of [`text=${text}`, `button:has-text("${text}")`, `[aria-label="${text}"]`]) {
      const el = page.locator(sel).first();
      if (await el.count().catch(() => 0)) {
        await el.click({ timeout: 2000 }).catch(() => {});
        return true;
      }
    }
    return false;
  }
  if (reject) { await clickByText(rejectText); await page.reload({ waitUntil: 'networkidle', timeout }).catch(() => {}); }
  if (accept) { await clickByText(acceptText); await page.reload({ waitUntil: 'networkidle', timeout }).catch(() => {}); }
  await page.waitForTimeout(500);

  const cookies = await context.cookies();
  const storage = await page.evaluate(() => {
    const ls = {}, ss = {};
    try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); ls[k] = String(localStorage.getItem(k)).slice(0, 64); } } catch {}
    try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); ss[k] = String(sessionStorage.getItem(k)).slice(0, 64); } } catch {}
    return { localStorage: ls, sessionStorage: ss };
  }).catch(() => ({ localStorage: {}, sessionStorage: {} }));

  await context.close();
  const nonEssentialCookies = cookies.filter((c) => !ESSENTIAL.test(c.name) && !CONSENT_KEY.test(c.name)).map((c) => c.name);
  const nonEssential = [
    ...nonEssentialCookies.map((n) => `cookie:${n}`),
    ...thirdParty.map((r) => `request:${r.url}`),
    ...Object.keys(storage.localStorage).filter((k) => !CONSENT_KEY.test(k)).map((k) => `localStorage:${k}`),
  ];
  return { cookies: cookies.map((c) => ({ name: c.name, domain: c.domain })), third_party_requests: thirdParty, storage, non_essential: nonEssential };
}

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
let result;
try {
  const before_consent = await stage(browser);
  const after_reject = await stage(browser, { reject: true });
  const after_accept = await stage(browser, { accept: true });
  result = {
    url, generated_at: new Date().toISOString(),
    before_consent: before_consent.non_essential,
    after_reject: after_reject.non_essential,
    after_accept: after_accept.non_essential,
    detail: { before_consent, after_reject, after_accept },
    violation: before_consent.non_essential.length > 0 || after_reject.non_essential.length > 0,
  };
} finally {
  await browser.close();
}

const json = JSON.stringify(result, null, 2);
if (out) writeFileSync(out, json + '\n');
console.log(json);
process.exit(0);
