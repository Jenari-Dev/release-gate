// release-gate k6 template: stress profile (step up beyond the expected load)
//
// Steps concurrency up past what you expect in production, to find where latency or errors
// break down first. Answers: what is the breaking point, and what fails first?
//
// Usage (local target, the default and the only one that needs no override):
//   BASE_URL=http://127.0.0.1:8000 PATHS=/,/api/health k6 run stress.js
//
// Environment:
//   BASE_URL            required. Must be loopback (127.x.x.x, localhost, [::1]) unless both
//                       RG_ALLOW_NONLOCAL=1 and RG_STAGING_CONFIRM=<exact host> are set, and then
//                       only for a staging environment you own. The script throws at init otherwise.
//   PATHS               comma-separated site-relative paths to GET (default "/")
//   RG_P95_MS           p95 latency threshold in ms (default 1500)
//   RG_ERROR_RATE       failed-request-rate threshold, 0..1 (default 0.05)
//   RG_SLEEP            think time between requests in seconds (default 1)
//   RG_SUMMARY          JSON summary output path (default k6-summary.json)
//   RG_VUS              expected virtual users; steps are multiples of this (default 10)
//   RG_STRESS_STEPS     comma-separated multipliers, in order (default "1,2,3,4")
//   RG_STEP             time spent on each step (default 30s)
//   RG_RECOVERY         ramp-down time at the end, to observe recovery (default 30s)
//
// STRESS TEST: only against a local instance or a staging environment you own. NEVER run against production (release-gate principle 3).
// Synthetic traffic only: no credentials, no personal data, GET requests only.
// k6 is not pinned in tools.lock.yaml; if `k6` is not installed this check is
// NOT-TESTED: tool unavailable.

import http from 'k6/http';
import { check, sleep } from 'k6';

// ---------------------------------------------------------------------------
// Target guard (identical in every release-gate k6 template; do not weaken).
// Runs at script init, so a bad target aborts the run before any request is made.
// ---------------------------------------------------------------------------
const RAW_BASE_URL = __ENV.BASE_URL;
if (!RAW_BASE_URL) {
  throw new Error('release-gate: BASE_URL is required (for example BASE_URL=http://127.0.0.1:8000)');
}
// scheme://host[:port] followed by "/", "?", "#" or end. Anything else (userinfo
// like http://127.0.0.1@elsewhere/, spaces, odd syntax) is rejected, not guessed at.
const URL_RE = /^(https?):\/\/(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+)(?::(\d{1,5}))?(?:[\/?#].*)?$/;
const urlMatch = URL_RE.exec(RAW_BASE_URL);
if (!urlMatch) {
  throw new Error('release-gate: BASE_URL is not a plain http(s)://host[:port] URL: refusing to run');
}
const TARGET_HOST = urlMatch[2].toLowerCase();
const IS_LOOPBACK = TARGET_HOST === 'localhost' || TARGET_HOST === '[::1]' || /^127(\.\d{1,3}){3}$/.test(TARGET_HOST);
if (!IS_LOOPBACK) {
  // Principle 3: dynamic tests only against targets the user owns and has put in
  // scope. A non-loopback target needs BOTH the override and a typed confirmation
  // that names the exact host (so a copy-pasted env block cannot hit something else).
  const override = __ENV.RG_ALLOW_NONLOCAL === '1';
  const confirmed = (__ENV.RG_STAGING_CONFIRM || '').toLowerCase() === TARGET_HOST;
  if (!override || !confirmed) {
    throw new Error(
      'release-gate: refusing non-loopback target "' + TARGET_HOST + '". Only run this against a staging ' +
      'environment you own: set RG_ALLOW_NONLOCAL=1 and RG_STAGING_CONFIRM=' + TARGET_HOST +
      '. Never point it at production or at a third party.');
  }
}
// Keep only scheme://host[:port]; any path or query in BASE_URL is dropped (use PATHS).
const BASE_URL = RAW_BASE_URL.replace(/^(https?:\/\/[^\/?#]+).*$/, '$1');

const PATHS = (__ENV.PATHS || '/').split(',').map((p) => p.trim()).filter((p) => p.length > 0);
for (const p of PATHS) {
  if (p.charAt(0) !== '/' || p.indexOf('://') !== -1 || /\s/.test(p) || p.indexOf('@') !== -1) {
    throw new Error('release-gate: PATHS entries must be site-relative and start with "/": ' + p);
  }
}

function envNum(name, dflt) {
  const raw = __ENV[name];
  if (raw === undefined || raw === '') return dflt;
  const n = Number(raw);
  if (!isFinite(n) || n < 0) throw new Error('release-gate: ' + name + ' must be a non-negative number');
  return n;
}
const P95_MS = envNum('RG_P95_MS', 1500);
const ERROR_RATE = envNum('RG_ERROR_RATE', 0.05);
const THINK_TIME_S = envNum('RG_SLEEP', 1);
const SUMMARY_PATH = __ENV.RG_SUMMARY || 'k6-summary.json';

function hitOnce() {
  // GET only: these templates never send a write. Redirects are not followed
  // (maxRedirects: 0 in options), so the target cannot bounce traffic elsewhere.
  const path = PATHS[Math.floor(Math.random() * PATHS.length)];
  const res = http.get(BASE_URL + path, { tags: { name: path } });
  check(res, { 'status is 2xx/3xx': (r) => r.status >= 200 && r.status < 400 });
  if (THINK_TIME_S > 0) sleep(THINK_TIME_S);
}

function baseOptions(stages) {
  return {
    stages: stages,
    maxRedirects: 0,
    userAgent: 'release-gate-k6',
    thresholds: {
      http_req_duration: ['p(95)<' + P95_MS],
      http_req_failed: ['rate<' + ERROR_RATE],
    },
    summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
    tags: { release_gate_profile: 'stress' },
  };
}

function summarize(data, shape) {
  const m = data.metrics || {};
  const pick = (name, key) => (m[name] && m[name].values ? m[name].values[key] : null);
  const meta = {
    profile: 'stress',
    shape: shape,
    target_host: TARGET_HOST,
    loopback: IS_LOOPBACK,
    paths: PATHS,
    thresholds: { p95_ms: P95_MS, error_rate: ERROR_RATE },
    results: {
      requests: pick('http_reqs', 'count'),
      rps: pick('http_reqs', 'rate'),
      p50_ms: pick('http_req_duration', 'med'),
      p95_ms: pick('http_req_duration', 'p(95)'),
      p99_ms: pick('http_req_duration', 'p(99)'),
      max_ms: pick('http_req_duration', 'max'),
      error_rate: pick('http_req_failed', 'rate'),
    },
  };
  const out = {};
  out[SUMMARY_PATH] = JSON.stringify({ release_gate: meta, k6: data }, null, 2);
  out.stdout =
    'release-gate k6 summary (' + meta.profile + ') target=' + TARGET_HOST + '\n' +
    '  requests=' + meta.results.requests + ' rps=' + meta.results.rps +
    ' p95_ms=' + meta.results.p95_ms + ' error_rate=' + meta.results.error_rate + '\n' +
    '  summary written to ' + SUMMARY_PATH + '\n';
  return out;
}

const VUS = envNum('RG_VUS', 10);
const STEP = __ENV.RG_STEP || '30s';
const RECOVERY = __ENV.RG_RECOVERY || '30s';
const STEPS = (__ENV.RG_STRESS_STEPS || '1,2,3,4').split(',').map((s) => Number(s.trim()));
for (const s of STEPS) {
  if (!isFinite(s) || s <= 0) throw new Error('release-gate: RG_STRESS_STEPS must be positive numbers, e.g. 1,2,3,4');
}

const stages = STEPS.map((mult) => ({ duration: STEP, target: Math.max(1, Math.round(VUS * mult)) }));
stages.push({ duration: RECOVERY, target: 0 });

export const options = baseOptions(stages);

export default function () {
  hitOnce();
}

export function handleSummary(data) {
  return summarize(data, { expected_vus: VUS, multipliers: STEPS, step: STEP, recovery: RECOVERY });
}
