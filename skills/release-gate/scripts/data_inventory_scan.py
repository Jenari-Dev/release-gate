#!/usr/bin/env python3
"""Statically scan a project and write a DRAFT data-inventory.yaml built from code.

    data_inventory_scan.py <project> [--out PATH] [--json] [--merge-existing] [--include-tests]

Every entry carries provenance {source: code, refs: ["relative/path:line", ...]}.
Nothing is executed or imported from the project; files are read as text only,
symlinks are never followed, and the output is validated against
schemas/data-inventory.schema.json before it is written.

What this scan is, and is not:
  * A regex / light-AST heuristic. A name-based classifier decides what counts as
    personal data. It finds what the code DECLARES or SENDS; it cannot prove what
    is collected at runtime, so absence from the draft is not evidence of absence.
  * Purposes, lawful basis, vendor roles, transfer regions and retention periods
    are decisions for the user. The scanner leaves them empty (or "unknown" /
    "none defined") and never invents them.
  * The draft is written with confirmed_by_user: false. A human must review it.

Detected (JS/TS, Python, HTML/templates, SQL, Prisma, plus generic Go / Rust /
Kotlin / Java / C# / Ruby / PHP schemas):
  fields         SQL CREATE TABLE columns, ORM / Pydantic / dataclass / Mongoose /
                 Sequelize / Prisma / TypeORM models, request bodies (req.body.x,
                 Form(...), request.form[...]), HTML inputs, analytics event payloads
  third_parties  absolute hosts in code (script/img/iframe tags, fetch/requests,
                 SDK imports, DB URLs) plus the analytics fields sent to them
  client_storage cookies (res.cookie, set_cookie, Set-Cookie, document.cookie,
                 session middleware), localStorage, sessionStorage, IndexedDB
  stores         databases, caches, queues, object storage, files written
  log_sinks      log statements that interpolate personal-data names
  rights         rights.deletion only when an erase operation (DELETE FROM on user
                 data, ORM delete near a deletion handler) is found; a route or
                 function that merely has a deletion-like name is NOT recorded as a
                 right (it is listed under scan.rights_name_only in --json output).
                 access_export / correction / opt_out_sale_share are found by name.

Loopback and private-network hosts are skipped unless the line or URL looks like
an analytics endpoint (analytic, track, telemetry, collect, beacon, pixel, ...):
a dev-server URL is not a third party, but a local stand-in for one deserves a
human look.

Exit codes: 0 ok, 1 produced inventory failed schema validation (a bug), 2 bad
arguments, 3 refused to overwrite a user-edited inventory (use --merge-existing
or a different --out).
"""
from __future__ import annotations

import argparse
import ast
import bisect
import json
import os
import re
import sys
import warnings
from pathlib import Path
from typing import Any, Callable, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rglib  # noqa: E402
from detect_stack import SKIP_DIRS as _STACK_SKIP_DIRS  # noqa: E402
from detect_stack import TEST_DIR_NAMES, TEST_FILE_RE  # noqa: E402

# --------------------------------------------------------------------------- limits / walk

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
MAX_TOTAL_BYTES = 200_000_000     # total source bytes read per pass; keeps a scan of a huge tree bounded and deterministic
MAX_LINE_LEN = 20_000            # a longer line means minified / generated code
MAX_REFS = 25
SKIP_DIRS = frozenset(_STACK_SKIP_DIRS) | frozenset({
    "site-packages", "bower_components", "third_party", "third-party", "thirdparty",
    "external", "externals", "vendors", "coverage", ".idea", ".vscode", ".nuxt",
    ".svelte-kit", ".turbo", ".cache", "__pypackages__", ".eggs", ".terraform",
    "target", "out", ".output", ".parcel-cache", ".yarn", ".pnpm-store",
})
EXTRA_TEST_DIRS = frozenset({"__mocks__", "fixtures", "testdata", "mocks", "specs", "test_data"})
SKIP_FILE_RE = re.compile(
    r"(\.min\.(js|css)$|\.map$|\.d\.ts$|\.bundle\.js$|\.chunk\.js$|"
    r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|poetry\.lock|"
    r"uv\.lock|Pipfile\.lock|pdm\.lock|go\.sum|Cargo\.lock|Gemfile\.lock|composer\.lock)$|\.lock$)")

JS_EXT = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"}
HTML_EXT = {".html", ".htm", ".xhtml", ".ejs", ".hbs", ".handlebars", ".njk", ".jinja", ".jinja2", ".j2",
            ".twig", ".liquid", ".erb", ".phtml", ".tmpl", ".mustache", ".pug", ".vue", ".svelte", ".astro"}
GENERIC_EXT = {".go", ".java", ".kt", ".kts", ".cs", ".rb", ".rs", ".swift", ".dart", ".scala", ".php", ".c", ".cc", ".cpp"}
CONFIG_NAME_RE = re.compile(
    r"(^|[\\/])(\.env(\..+)?|.+\.env|(config|settings|secrets?|appsettings|application|default|production|development|staging)"
    r"[^/\\]*\.(ya?ml|json|toml|ini|cfg|properties))$", re.I)

DOB_NOTE = "date of birth / age is collected: confirm whether children under 13/16 can use the service"

# --------------------------------------------------------------------------- classifier

LOG_SKIP_CLASSES = frozenset({"content", "other"})
NOT_PERSONAL_LAST = frozenset({"at", "ts", "timestamp", "count", "counts", "size", "length", "enabled", "disabled", "flag",
                               "verified", "confirmed"})
NOT_PERSONAL_ANY = frozenset({"csrf", "xsrf", "count", "counts", "limit", "max", "min", "ttl", "expires", "expiry", "expiration", "type"})
USER_TABLE_WORDS = frozenset({
    "user", "account", "customer", "member", "profile", "person", "people", "employee", "patient",
    "student", "subscriber", "contact", "author", "owner", "client", "visitor", "lead", "driver",
})

_RULES: list[tuple[str, str | None, frozenset[str]]] = [
    ("children", None, frozenset({"minor", "isminor", "guardian", "coppa", "parentalconsent", "parentemail", "underage",
                                    "under13", "under16", "isunder13", "ischild", "childname", "childage"})),
    ("sensitive", "health", frozenset({"health", "medical", "diagnosis", "diagnoses", "symptom", "symptoms", "medication",
                                         "medications", "allergy", "allergies", "disability", "pregnancy", "pregnant",
                                         "bloodtype", "hiv", "prescription"})),
    ("sensitive", "biometric", frozenset({"biometric", "biometrics", "faceid", "faceprint", "voiceprint", "retina", "iris"})),
    ("sensitive", "government-id", frozenset({"ssn", "passport", "nationalid", "taxid", "driverlicense", "driverslicense"})),
    ("sensitive", "ethnicity", frozenset({"ethnicity", "race", "racial"})),
    ("sensitive", "religion", frozenset({"religion", "religious"})),
    ("sensitive", "sexual-orientation", frozenset({"sexuality", "sexualorientation"})),
    ("sensitive", "political-opinion", frozenset({"political", "politics"})),
    ("sensitive", "trade-union", frozenset({"tradeunion"})),
    ("sensitive", "criminal-record", frozenset({"criminal", "conviction", "convictions"})),
    ("credential", None, frozenset({"password", "passwd", "pwd", "passphrase", "secret", "token", "otp", "totp", "mfa",
                                      "apikey", "accesskey", "secretkey", "privatekey", "sessionid", "sessiontoken",
                                      "authtoken", "authorization", "credential", "credentials", "salt", "jwt", "bearer"})),
    ("financial", None, frozenset({"creditcard", "debitcard", "paymentcard", "cardnumber", "cvv", "cvc", "iban", "bic", "swift",
                                    "routing", "routingnumber", "accountnumber", "bankaccount", "balance", "salary",
                                    "income", "payout", "bank", "ccnumber", "cardholder"})),
    ("location", None, frozenset({"lat", "lng", "lon", "latitude", "longitude", "geo", "geolocation", "gps", "ip",
                                    "ipaddress", "ipaddr", "clientip", "remoteaddr", "remoteaddress", "location",
                                    "coords", "coordinates", "city", "country", "geohash", "xforwardedfor"})),
    ("device-telemetry", None, frozenset({"useragent", "ua", "device", "deviceid", "fingerprint", "browser", "imei",
                                            "idfa", "gaid", "referrer", "referer"})),
    ("contact", None, frozenset({"email", "emailaddress", "mail", "phone", "phonenumber", "telephone", "tel", "mobile",
                                   "msisdn", "fax", "address", "street", "streetaddress", "zip", "zipcode", "postal",
                                   "postalcode", "postcode", "addr", "whatsapp"})),
    ("identifier", None, frozenset({"username", "userid", "uid", "handle", "nickname", "nick", "displayname", "fullname",
                                     "firstname", "lastname", "surname", "givenname", "familyname", "accountid",
                                     "customerid", "memberid", "ownerid", "authorid", "author", "profileid",
                                     "patientid", "studentid", "subscriberid", "userref"})),
    ("other", "dob", frozenset({"dob", "birthday", "birthdate", "birth", "dateofbirth", "yob", "age", "born"})),
    ("other", None, frozenset({"gender", "sex", "nationality", "occupation", "employer", "jobtitle", "birthplace"})),
    ("content", None, frozenset({"body", "comment", "comments", "message", "msg", "bio", "content", "feedback",
                                   "note", "notes", "caption", "avatar", "photo", "picture", "selfie", "attachment"})),
]
# autocomplete= hints for inputs whose name tells us nothing
_AUTOCOMPLETE = {
    "email": "contact", "tel": "contact", "street-address": "contact", "address-line1": "contact",
    "postal-code": "contact", "cc-number": "financial", "cc-csc": "financial", "cc-exp": "financial",
    "bday": "other", "username": "identifier", "given-name": "identifier", "family-name": "identifier",
    "name": "identifier", "current-password": "credential", "new-password": "credential",
    "one-time-code": "credential",
}
# type annotation overrides (Pydantic and friends)
_TYPE_HINTS = [
    (re.compile(r"\bEmailStr\b|\bEmailField\b"), "contact"),
    (re.compile(r"\bSecretStr\b|\bSecretBytes\b"), "credential"),
    (re.compile(r"\bPhoneNumber\b|\bPhoneNumberField\b"), "contact"),
    (re.compile(r"\bIPv[46]Address\b|\bIPvAnyAddress\b|\bGenericIPAddressField\b"), "location"),
]


def name_tokens(name: str) -> list[str]:
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name))
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", s)
    return [t for t in re.split(r"[^A-Za-z0-9]+", s.lower()) if t]


def _candidates(toks: list[str]) -> set[str]:
    out = set(toks)
    for n in (2, 3):
        for i in range(len(toks) - n + 1):
            out.add("".join(toks[i:i + n]))
    out.add("".join(toks))
    return out


def user_like_table(table: str | None) -> bool:
    if not table:
        return False
    return any(t.rstrip("s") in USER_TABLE_WORDS or t in USER_TABLE_WORDS for t in name_tokens(table))


def classify(name: str, table: str | None = None) -> tuple[str, str | None] | None:
    """Name-based classification. Returns (classification, sensitive_kind) or None.

    `sensitive_kind == "dob"` is an internal marker (date of birth / age); Acc.add_field
    turns it into a note and drops it before output.
    """
    toks = name_tokens(name)
    if not toks:
        return None
    if toks == ["id"] or toks == ["name"]:
        return ("identifier", None) if user_like_table(table) else None
    if toks[-1] in NOT_PERSONAL_LAST or "".join(toks) == "serialversionuid":
        return None
    if NOT_PERSONAL_ANY.intersection(toks):
        return None
    cand = _candidates(toks)
    if "address" in cand and cand & {"url", "ip", "mac", "web", "wallet", "contract"}:
        cand.discard("address")
    if "mobile" in cand and toks[0] in {"is", "has"}:
        cand.discard("mobile")
    for cls, kind, words in _RULES:
        if cand & words:
            if cls in ("content", "other") and toks[-1] in {"id", "ids", "uuid", "key", "hash"}:
                return None                       # message_id, content_hash: a reference, not the content
            return cls, kind
    return None


def classify_type(annotation: str) -> str | None:
    for rx, cls in _TYPE_HINTS:
        if rx.search(annotation):
            return cls
    return None


# --------------------------------------------------------------------------- vendors

# (host regex, vendor, purpose, category)
VENDOR_HOSTS: list[tuple[re.Pattern[str], str, str, str]] = [(re.compile(p, re.I), v, pu, c) for p, v, pu, c in [
    (r"(^|\.)(google-analytics\.com|analytics\.google\.com|googletagmanager\.com)$", "Google Analytics / Tag Manager", "analytics", "analytics"),
    (r"(^|\.)(doubleclick\.net|googlesyndication\.com|googleadservices\.com)$", "Google Ads", "advertising", "advertising"),
    (r"(^|\.)(connect\.facebook\.net|graph\.facebook\.com|facebook\.com)$", "Meta (Facebook)", "advertising / social plugins", "advertising"),
    (r"(^|\.)(hotjar\.com|hotjar\.io)$", "Hotjar", "analytics / session replay", "analytics"),
    (r"(^|\.)clarity\.ms$", "Microsoft Clarity", "analytics / session replay", "analytics"),
    (r"(^|\.)mixpanel\.com$", "Mixpanel", "analytics", "analytics"),
    (r"(^|\.)(segment\.(com|io)|cdn\.segment\.com)$", "Segment", "analytics", "analytics"),
    (r"(^|\.)amplitude\.com$", "Amplitude", "analytics", "analytics"),
    (r"(^|\.)posthog\.com$", "PostHog", "analytics", "analytics"),
    (r"(^|\.)plausible\.io$", "Plausible", "analytics", "analytics"),
    (r"(^|\.)(heap\.io|heapanalytics\.com)$", "Heap", "analytics", "analytics"),
    (r"(^|\.)fullstory\.com$", "FullStory", "analytics / session replay", "analytics"),
    (r"(^|\.)logrocket\.(com|io)$", "LogRocket", "session replay / monitoring", "analytics"),
    (r"(^|\.)sentry\.io$", "Sentry", "error monitoring", "monitoring"),
    (r"(^|\.)datadoghq\.(com|eu)$", "Datadog", "monitoring", "monitoring"),
    (r"(^|\.)(newrelic\.com|nr-data\.net)$", "New Relic", "monitoring", "monitoring"),
    (r"(^|\.)(bugsnag\.com|rollbar\.com)$", "Error monitoring service", "error monitoring", "monitoring"),
    (r"(^|\.)(intercom\.io|intercomcdn\.com)$", "Intercom", "customer messaging", "support"),
    (r"(^|\.)(hs-scripts\.com|hubspot\.com|hsforms\.com)$", "HubSpot", "marketing / CRM", "marketing"),
    (r"(^|\.)sendgrid\.(com|net)$", "SendGrid", "transactional email", "email"),
    (r"(^|\.)mailgun\.(net|org|com)$", "Mailgun", "transactional email", "email"),
    (r"(^|\.)(mailchimp\.com|list-manage\.com)$", "Mailchimp", "email marketing", "email"),
    (r"(^|\.)postmarkapp\.com$", "Postmark", "transactional email", "email"),
    (r"(^|\.)twilio\.com$", "Twilio", "SMS / voice", "messaging"),
    (r"(^|\.)stripe\.(com|network)$", "Stripe", "payments", "payments"),
    (r"(^|\.)paypal(objects)?\.com$", "PayPal", "payments", "payments"),
    (r"(^|\.)braintreegateway\.com$", "Braintree", "payments", "payments"),
    (r"(^|\.)adyen\.com$", "Adyen", "payments", "payments"),
    (r"(^|\.)(fonts\.googleapis\.com|fonts\.gstatic\.com)$", "Google Fonts", "web fonts (visitor IP is sent to Google)", "cdn"),
    (r"(^|\.)(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|cdn\.tailwindcss\.com|code\.jquery\.com|ajax\.googleapis\.com)$", "Public CDN", "asset delivery (visitor IP is sent to the CDN)", "cdn"),
    (r"(^|\.)(youtube\.com|youtube-nocookie\.com|ytimg\.com)$", "YouTube", "embedded video", "embed"),
    (r"(^|\.)vimeo\.com$", "Vimeo", "embedded video", "embed"),
    (r"(^|\.)(firebaseio\.com|firebase\.google\.com|firebaseapp\.com|googleapis\.com)$", "Google / Firebase", "backend services", "backend"),
    (r"(^|\.)amazonaws\.com$", "Amazon Web Services", "cloud hosting / storage", "backend"),
    (r"(^|\.)mongodb\.net$", "MongoDB Atlas", "database hosting", "backend"),
    (r"(^|\.)supabase\.(co|com|io)$", "Supabase", "database / auth hosting", "backend"),
    (r"(^|\.)(neon\.tech|planetscale\.com|upstash\.io|redislabs\.com|redis-cloud\.com)$", "Managed database", "database hosting", "backend"),
    (r"(^|\.)openai\.com$", "OpenAI", "AI inference (prompt data is sent to the vendor)", "ai"),
    (r"(^|\.)anthropic\.com$", "Anthropic", "AI inference (prompt data is sent to the vendor)", "ai"),
    (r"(^|\.)(recaptcha\.net|hcaptcha\.com|challenges\.cloudflare\.com)$", "CAPTCHA provider", "bot protection", "security"),
]]
ANALYTICS_CATEGORIES = frozenset({"analytics", "advertising", "monitoring"})

# cookies a vendor script is documented to set; inferred from script inclusion, not observed
VENDOR_COOKIES: dict[str, list[tuple[str, str]]] = {
    "Google Analytics / Tag Manager": [("_ga", "analytics"), ("_gid", "analytics")],
    "Meta (Facebook)": [("_fbp", "advertising")],
    "Hotjar": [("_hjSessionUser_*", "analytics")],
    "Microsoft Clarity": [("_clck", "analytics"), ("_clsk", "analytics")],
}

_IMP = r"""(?:require\(\s*|from\s+|import\s+)['"]?"""
# SDK import -> (canonical host, vendor, purpose, category)
SDK_IMPORTS: list[tuple[re.Pattern[str], str, str, str, str]] = [(re.compile(p), h, v, pu, c) for p, h, v, pu, c in [
    (_IMP + r"(?:posthog-node|posthog-js|posthog)\b", "posthog.com", "PostHog", "analytics", "analytics"),
    (_IMP + r"mixpanel(?:-browser)?\b", "api.mixpanel.com", "Mixpanel", "analytics", "analytics"),
    (_IMP + r"(?:@segment/analytics-(?:next|node)|analytics-node|analytics-python|segment)\b", "api.segment.io", "Segment", "analytics", "analytics"),
    (_IMP + r"(?:@amplitude/[\w-]+|amplitude-js|amplitude)\b", "api.amplitude.com", "Amplitude", "analytics", "analytics"),
    (_IMP + r"(?:@sentry/[\w-]+|sentry_sdk)\b", "sentry.io", "Sentry", "error monitoring", "monitoring"),
    (_IMP + r"stripe\b", "api.stripe.com", "Stripe", "payments", "payments"),
    (_IMP + r"(?:@sendgrid/mail|sendgrid)\b", "api.sendgrid.com", "SendGrid", "transactional email", "email"),
    (_IMP + r"twilio\b", "api.twilio.com", "Twilio", "SMS / voice", "messaging"),
    (_IMP + r"(?:mailgun\.js|mailgun-js|mailgun)\b", "api.mailgun.net", "Mailgun", "transactional email", "email"),
    (_IMP + r"(?:firebase-admin|firebase)\b", "firebaseio.com", "Google / Firebase", "backend services", "backend"),
    (_IMP + r"openai\b", "api.openai.com", "OpenAI", "AI inference (prompt data is sent to the vendor)", "ai"),
    (_IMP + r"(?:@anthropic-ai/sdk|anthropic)\b", "api.anthropic.com", "Anthropic", "AI inference (prompt data is sent to the vendor)", "ai"),
    (_IMP + r"logrocket\b", "logrocket.com", "LogRocket", "session replay / monitoring", "analytics"),
]]

# --------------------------------------------------------------------------- stores

# (regex on a line that looks like an import / connect, kind, name)
STORE_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [(re.compile(p, re.I), k, n) for p, k, n in [
    (r"""node:sqlite|better-sqlite3|\bsqlite3\b|aiosqlite|sqlite://|sqlite:///|\bsql\.js\b""", "database", "sqlite"),
    (r"""require\(\s*['"]pg['"]|from\s+['"]pg['"]|\bpsycopg2?\b|\basyncpg\b|postgres(?:ql)?(?:\+\w+)?://|from\s+['"]postgres['"]|django\.db\.backends\.postgresql""", "database", "postgresql"),
    (r"""\bmysql2?\b|\bpymysql\b|\bmysqlclient\b|\bmariadb\b|mysql://|django\.db\.backends\.mysql""", "database", "mysql"),
    (r"""\bmongoose\b|mongodb(?:\+srv)?://|\bpymongo\b|\bmotor\.motor_asyncio\b|require\(\s*['"]mongodb['"]|from\s+['"]mongodb['"]|\bmongoengine\b""", "database", "mongodb"),
    (r"""\bmssql\b|\bpyodbc\b|sqlserver://""", "database", "sql-server"),
    (r"""\bdynamodb\b|\bDynamoDBClient\b""", "database", "dynamodb"),
    (r"""\bfirestore\b""", "database", "firestore"),
    (r"""@supabase/supabase-js|\bfrom\s+supabase\b|\bimport\s+supabase\b""", "database", "supabase"),
    (r"""\bioredis\b|require\(\s*['"]redis['"]|from\s+['"]redis['"]|\bimport\s+redis\b|\bfrom\s+redis\b|\baioredis\b|rediss?://""", "cache", "redis"),
    (r"""\bmemcached?\b|\bpymemcache\b""", "cache", "memcached"),
    (r"""@aws-sdk/client-s3|\bS3Client\b|\bboto3\b.*['"]s3['"]|['"]s3['"].*\bboto3\b|\bminio\b""", "object-storage", "s3"),
    (r"""@google-cloud/storage|google\.cloud\s+import\s+storage|google\.cloud\.storage""", "object-storage", "gcs"),
    (r"""@azure/storage-blob|azure\.storage\.blob""", "object-storage", "azure-blob"),
    (r"""\bcloudinary\b""", "object-storage", "cloudinary"),
    (r"""\bamqplib\b|\bpika\b|amqps?://|\bkombu\b|\bcelery\b""", "queue", "amqp"),
    (r"""\bkafkajs\b|\bconfluent_kafka\b|\bkafka-python\b""", "queue", "kafka"),
    (r"""\bbullmq\b|require\(\s*['"]bull['"]|from\s+['"]bull['"]""", "queue", "bull"),
    (r"""@aws-sdk/client-sqs|\bboto3\b.*['"]sqs['"]""", "queue", "sqs"),
    (r"""\belasticsearch\b|@elastic/|\bopensearch\b""", "search", "elasticsearch"),
    (r"""\balgoliasearch\b|\bmeilisearch\b|\btypesense\b""", "search", "hosted-search"),
]]
IMPORTISH_RE = re.compile(r"\b(import|from|require|use|using|connect|create_engine|new|include|provider|ENGINE|client|Client|createClient|createPool|open)\b|://")
FILE_WRITE_JS_RE = re.compile(r"\b(?:fs(?:\.promises)?|fsp|fse|fsExtra)\.(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|outputFile)\s*\(")
FILE_HANDLER_RE = re.compile(r"\b(?:FileHandler|RotatingFileHandler|TimedRotatingFileHandler|WatchedFileHandler|pino\.destination|FileAppender)\s*\(")
PY_OPEN_RE = re.compile(r"(?<![\w.])open\s*\(")
WINSTON_FILE_RE = re.compile(r"\bfilename\s*:\s*")
MULTER_RE = re.compile(r"\bmulter\s*\(")

# --------------------------------------------------------------------------- helpers: text

_STR_C = r"""("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)"""
_C_STRIP_RE = re.compile(_STR_C + r"|(//[^\n]*)|(/\*.*?\*/)", re.S)
_PY_STRIP_RE = re.compile(r"""('''.*?'''|\"\"\".*?\"\"\"|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|(#[^\n]*)""", re.S)
_SQL_STRIP_RE = re.compile(r"""('(?:''|[^'])*'|"(?:[^"\n])*")|(--[^\n]*)|(/\*.*?\*/)""", re.S)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_CONF_STRIP_RE = re.compile(r"(?m)(^|\s)#.*$")
_BLANK_RE = re.compile(r"[^\n]")


def _blank(m: re.Match[str]) -> str:
    text = m.group(0)
    return " " * len(text) if "\n" not in text else _BLANK_RE.sub(" ", text)


def strip_comments(text: str, kind: str) -> str:
    """Blank out comments, keeping offsets and newlines (so line numbers stay valid)."""
    if kind == "py":
        return _PY_STRIP_RE.sub(lambda m: m.group(0) if m.group(1) else _blank(m), text)
    if kind == "sql":
        return _SQL_STRIP_RE.sub(lambda m: m.group(0) if m.group(1) else _blank(m), text)
    if kind == "html":
        return _HTML_COMMENT_RE.sub(_blank, text)
    if kind == "config":
        return _CONF_STRIP_RE.sub(lambda m: m.group(1) + _BLANK_RE.sub(" ", m.group(0)[len(m.group(1)):]), text)
    if kind in ("js", "prisma", "generic", "css"):
        return _C_STRIP_RE.sub(lambda m: m.group(0) if m.group(1) else _blank(m), text)
    return text


def _skip_quoted(s: str, j: int, end: int) -> int:
    """s[j] is a quote char; return the index just past the matching quote (j+1 if unterminated on the line)."""
    q = s[j]
    if q in "\"'" and s[j:j + 3] == q * 3:
        k = s.find(q * 3, j + 3, end)
        return end if k < 0 else k + 3
    k = j + 1
    while k < end:
        c = s[k]
        if c == "\\":
            k += 2
            continue
        if c == q:
            return k + 1
        if c == "\n" and q != "`":
            return j + 1                 # stray apostrophe: do not swallow the rest of the file
        k += 1
    return j + 1


_PAIRS = {"(": ")", "[": "]", "{": "}"}


def match_close(s: str, i: int, limit: int = 30_000) -> int:
    """s[i] is an opening bracket; return the index of its match or -1."""
    open_ch = s[i]
    close_ch = _PAIRS[open_ch]
    depth = 0
    j = i
    end = min(len(s), i + limit)
    while j < end:
        c = s[j]
        if c in "\"'`":
            j = _skip_quoted(s, j, end)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def split_top(s: str) -> list[tuple[int, str]]:
    """Split on top-level commas; return (offset, text) pairs."""
    out: list[tuple[int, str]] = []
    depth = 0
    start = 0
    j = 0
    n = len(s)
    while j < n:
        c = s[j]
        if c in "\"'`":
            j = _skip_quoted(s, j, n)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append((start, s[start:j]))
            start = j + 1
        j += 1
    if s[start:].strip():
        out.append((start, s[start:]))
    return out


def call_args(code: str, open_idx: int) -> tuple[list[tuple[int, str]], int]:
    """Args of the call whose '(' is at open_idx: ([(abs_offset, text)], index_of_close or -1)."""
    close = match_close(code, open_idx)
    if close < 0:
        return [], -1
    inner = code[open_idx + 1:close]
    return [(open_idx + 1 + off, txt) for off, txt in split_top(inner)], close


_STR_LIT_RE = re.compile(r"""^\s*[fFrRbBuU]{0,2}(['"`])((?:\\.|(?!\1).)*)\1\s*$""", re.S)
_IDENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def str_literal(text: str) -> str | None:
    m = _STR_LIT_RE.match(text)
    return m.group(2) if m else None


_KEY_RE = re.compile(r"""^(?:\[\s*)?(?:'([\w$-]+)'|"([\w$-]+)"|([A-Za-z_$][\w$]*))(?:\s*\])?\s*(?::\s*(.*)|=\s*(.*)|\(.*)?$""", re.S)


def object_keys(text: str, depth: int = 0) -> list[tuple[str, str]]:
    """Top-level (key, value_text) pairs of an object literal / kwargs-ish text (without the outer braces)."""
    out: list[tuple[str, str]] = []
    for _, part in split_top(text):
        part = part.strip()
        if not part or part.startswith("..."):
            continue
        m = _KEY_RE.match(part)
        if not m:
            continue
        key = m.group(1) or m.group(2) or m.group(3)
        value = ((m.group(4) if m.group(4) is not None else m.group(5)) or key).strip()
        out.append((key, value))
        if depth < 2 and value.startswith("{"):
            close = match_close(value, 0)
            if close > 0:
                out.extend(object_keys(value[1:close], depth + 1))
    return out


# --------------------------------------------------------------------------- source files

class Source:
    __slots__ = ("rel", "raw", "kind", "code", "_starts")

    def __init__(self, rel: str, raw: str, kind: str) -> None:
        self.rel = rel
        self.raw = raw
        self.kind = kind
        self.code = strip_comments(raw, kind)
        starts = [0]
        for m in re.finditer("\n", raw):
            starts.append(m.end())
        self._starts = starts

    def line(self, idx: int) -> int:
        return bisect.bisect_right(self._starts, max(idx, 0))

    def ref(self, idx: int) -> str:
        return f"{self.rel}:{self.line(idx)}"

    def line_start(self, idx: int) -> int:
        return self._starts[self.line(idx) - 1]

    def line_text(self, idx: int) -> str:
        start = self.line_start(idx)
        end = self.code.find("\n", start)
        return self.code[start:end if end >= 0 else len(self.code)]


def file_kind(rel: str) -> str | None:
    p = Path(rel)
    ext = p.suffix.lower()
    if ext in JS_EXT:
        return "js"
    if ext == ".py":
        return "py"
    if ext in HTML_EXT:
        return "html"
    if ext == ".sql":
        return "sql"
    if ext == ".prisma":
        return "prisma"
    if ext in (".css", ".scss"):
        return "css"
    if ext in GENERIC_EXT:
        return "generic"
    if CONFIG_NAME_RE.search(rel) and (ext in {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".properties", ".env"}
                                       or p.name.startswith(".env") or ext == ""):
        return "config"
    return None


def walk_project(root: Path, include_tests: bool, meta: dict[str, Any]) -> list[tuple[str, str]]:
    """Deterministic list of (relative posix path, kind). Symlinks are never followed."""
    found: list[tuple[str, str]] = []
    test_dirs = set(TEST_DIR_NAMES) | EXTRA_TEST_DIRS
    for cur, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(cur)
        rel_dir = here.relative_to(root).as_posix()
        keep = []
        for d in sorted(dirnames):
            full = here / d
            if d in SKIP_DIRS or full.is_symlink() or (full / "pyvenv.cfg").exists():
                continue
            if not include_tests and d.lower() in test_dirs:
                meta["skipped_test_dirs"] += 1
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            full = here / f
            rel = f"{rel_dir}/{f}" if rel_dir != "." else f
            if full.is_symlink() or SKIP_FILE_RE.search(rel):
                continue
            kind = file_kind(rel)
            if kind is None:
                continue
            if not include_tests and TEST_FILE_RE.search(f):
                meta["skipped_test_files"] += 1
                continue
            if len(found) >= MAX_FILES:
                meta["truncated"] = True
                return found
            found.append((rel, kind))
    return found


def load_source(root: Path, rel: str, kind: str, meta: dict[str, Any]) -> Source | None:
    path = root / rel
    try:
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            meta["skipped_large"] += 1
            return None
        if meta["bytes_read"] + size > MAX_TOTAL_BYTES:
            meta["truncated"] = True
            meta["skipped_budget"] += 1
            return None
        data = path.read_bytes()
    except OSError:
        return None
    meta["bytes_read"] += len(data)
    if b"\x00" in data[:8192]:
        meta["skipped_binary"] += 1
        return None
    text = data.decode("utf-8", errors="replace")
    if max((len(x) for x in text.split("\n")), default=0) > MAX_LINE_LEN:
        meta["skipped_minified"] += 1
        return None
    return Source(rel, text, kind)


# --------------------------------------------------------------------------- accumulator

VIA_ORDER = ("form", "api-body", "model", "analytics-event", "log", "cookie", "third-party", "derived")


class Acc:
    """Collects raw detections before they are turned into schema entries."""

    def __init__(self) -> None:
        self.fields: dict[str, dict[str, Any]] = {}
        self.third: dict[str, dict[str, Any]] = {}
        self.storage: dict[tuple[str, str], dict[str, Any]] = {}
        self.stores: dict[tuple[str, str], dict[str, Any]] = {}
        self.logs: dict[tuple[str, int], dict[str, Any]] = {}
        self.rights: dict[str, dict[str, Any]] = {}
        self.rights_name_only: dict[str, set[str]] = {}
        self.unclassified: list[dict[str, str]] = []
        self.warnings: list[str] = []
        self.retention_refs: list[str] = []
        self.url_vars: dict[str, str] = {}                  # CONST_NAME -> host key
        self.event_files: dict[str, dict[str, Any]] = {}    # rel -> fields / words / hosts / sdk
        self.pending_py: list[dict[str, Any]] = []
        self.request_models: set[str] = set()

    def add_field(self, name: str, cls: str, via: str, ref: str, *, kind: str | None = None, note: str | None = None,
                  usage: bool = True, def_lines: Iterable[str] = ()) -> None:
        if kind == "dob":
            kind, note = None, note or DOB_NOTE
        rec = self.fields.setdefault(name, {
            "classification": cls, "sensitive_kind": kind, "via": set(), "refs": set(), "notes": set(),
            "bare": name.rsplit(".", 1)[-1], "def_lines": set(), "usage": usage,
        })
        rec["via"].add(via)
        rec["refs"].add(ref)
        rec["def_lines"].add(ref)
        rec["def_lines"].update(def_lines)
        rec["usage"] = rec["usage"] and usage
        if note:
            rec["notes"].add(note)

    def add_third(self, host: str, ref: str, *, vendor: str | None = None, purpose: str | None = None,
                  category: str | None = None, note: str | None = None, analytics_like: bool = False) -> None:
        rec = self.third.setdefault(host, {"refs": set(), "vendor": vendor, "purpose": purpose, "category": category,
                                           "notes": set(), "data_sent": set(), "analytics_like": False})
        rec["refs"].add(ref)
        rec["vendor"] = rec["vendor"] or vendor
        rec["purpose"] = rec["purpose"] or purpose
        rec["category"] = rec["category"] or category
        rec["analytics_like"] = rec["analytics_like"] or analytics_like
        if note:
            rec["notes"].add(note)

    def add_storage(self, mech: str, name: str, ref: str, *, set_by: str = "first-party", expiry: str | None = None,
                    note: str | None = None, necessity: str | None = None) -> None:
        rec = self.storage.setdefault((mech, name), {"refs": set(), "set_by": set_by, "expiry": expiry, "notes": set(),
                                                     "necessity": necessity})
        rec["refs"].add(ref)
        rec["expiry"] = rec["expiry"] or expiry
        rec["necessity"] = rec["necessity"] or necessity
        if note:
            rec["notes"].add(note)

    def add_store(self, kind: str, name: str, ref: str, note: str | None = None) -> None:
        rec = self.stores.setdefault((kind, name), {"refs": set(), "notes": set()})
        rec["refs"].add(ref)
        if note:
            rec["notes"].add(note)

    def add_right(self, key: str, ref: str, note: str) -> None:
        rec = self.rights.setdefault(key, {"refs": set(), "notes": set()})
        rec["refs"].add(ref)
        rec["notes"].add(note)

    def event_file(self, rel: str) -> dict[str, Any]:
        return self.event_files.setdefault(rel, {"fields": set(), "words": set(), "hosts": set(), "sdk": set(), "vendors": set()})


def ref_sort_key(ref: str) -> tuple[str, int]:
    path, _, line = ref.rpartition(":")
    return path, int(line) if line.isdigit() else 0


def sorted_refs(refs: Iterable[str]) -> list[str]:
    return sorted(set(refs), key=ref_sort_key)


# --------------------------------------------------------------------------- context

class Ctx:
    """Cross-file bookkeeping and tiny per-file constant resolution."""

    def __init__(self) -> None:
        self.file_hosts: dict[str, set[str]] = {}
        self.file_sdk_hosts: dict[str, set[str]] = {}

    @staticmethod
    def const_int(src: Source, name: str) -> str | None:
        m = re.search(r"(?m)^[ \t]*(?:const[ \t]+|let[ \t]+|var[ \t]+|export[ \t]+)?" + re.escape(name) + r"\s*(?::[^=\n]+)?[:=]\s*(\d{2,5})\b", src.code)
        return m.group(1) if m else None

    def mark_event_file(self, src: Source, acc: Acc) -> None:
        ev = acc.event_file(src.rel)
        if not ev["words"]:
            ev["words"] = set(_IDENT_RE.findall(src.code))
        ev["hosts"] |= self.file_hosts.get(src.rel, set())
        ev["sdk"] |= self.file_sdk_hosts.get(src.rel, set())


# --------------------------------------------------------------------------- SQL / schema extractors

_CREATE_TABLE_RE = re.compile(r"""\bCREATE\s+(?:(?:GLOBAL\s+|LOCAL\s+)?(?:TEMP(?:ORARY)?|UNLOGGED)\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`"\[]?[\w.\-]+[`"\]]?)\s*\(""", re.I)
_ALTER_ADD_RE = re.compile(r"""\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?([`"\[]?[\w.\-]+[`"\]]?)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?([`"\[]?\w+[`"\]]?)\s+[A-Za-z]""", re.I)
_CONSTRAINT_WORDS = frozenset({"PRIMARY", "UNIQUE", "FOREIGN", "CONSTRAINT", "CHECK", "INDEX", "KEY", "FULLTEXT", "EXCLUDE", "LIKE", "PERIOD"})
_COL_WORD_RE = re.compile(r"""[`"\[]?(\w+)""")


def _unquote(ident: str) -> str:
    return ident.strip("`\"[]'")


def add_model_field(acc: Acc, src: Source, idx: int, table: str, col: str, span: Iterable[str] = ()) -> None:
    name = f"{table}.{col}"
    res = classify(col, table)
    if res is None:
        if len(acc.unclassified) < 500:
            acc.unclassified.append({"name": name, "ref": src.ref(idx)})
        return
    acc.add_field(name, res[0], "model", src.ref(idx), kind=res[1], def_lines=span)


_NO_USAGE_PREFIXES = ("request.header.", "request.ip", "cookie.")     # the read itself is the use


def add_request_field(acc: Acc, src: Source, idx: int, name: str, res: tuple[str, str | None], via: str) -> None:
    acc.add_field(name, res[0], via, src.ref(idx), kind=res[1], usage=not name.startswith(_NO_USAGE_PREFIXES))


def x_sql(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    if not re.search(r"(?i)\bCREATE\b|\bALTER\b", code):
        return
    for m in _CREATE_TABLE_RE.finditer(code):
        table = _unquote(m.group(1)).split(".")[-1]
        open_idx = m.end() - 1
        close = match_close(code, open_idx)
        if close < 0:
            continue
        inner = code[open_idx + 1:close]
        span = {f"{src.rel}:{ln}" for ln in range(src.line(open_idx), src.line(close) + 1)}
        for off, seg in split_top(inner):
            stripped = seg.strip()
            wm = _COL_WORD_RE.match(stripped)
            if not wm or wm.group(1).upper() in _CONSTRAINT_WORDS:
                continue
            idx = open_idx + 1 + off + (len(seg) - len(seg.lstrip()))
            add_model_field(acc, src, idx, table, wm.group(1), span)
    for m in _ALTER_ADD_RE.finditer(code):
        add_model_field(acc, src, m.start(2), _unquote(m.group(1)).split(".")[-1], _unquote(m.group(2)))


def x_prisma(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    scalars = {"String", "Int", "Float", "Boolean", "DateTime", "Json", "BigInt", "Decimal", "Bytes"}
    for m in re.finditer(r"^[ \t]*model\s+(\w+)\s*\{", code, re.M):
        close = match_close(code, m.end() - 1)
        if close < 0:
            continue
        body_start = m.end()
        for lm in re.finditer(r"^[ \t]*(\w+)\s+(\w+)", code[body_start:close], re.M):
            if lm.group(2) in scalars:
                add_model_field(acc, src, body_start + lm.start(1), m.group(1), lm.group(1))
    for m in re.finditer(r"""\bprovider\s*=\s*['"](postgresql|postgres|mysql|sqlite|mongodb|sqlserver|cockroachdb)['"]""", code):
        name = {"postgres": "postgresql", "cockroachdb": "postgresql", "sqlserver": "sql-server"}.get(m.group(1), m.group(1))
        acc.add_store("database", name, src.ref(m.start()))


def _object_after(code: str, idx: int) -> tuple[int, int] | None:
    j = idx
    while j < len(code) and code[j] in " \t\r\n":
        j += 1
    if j < len(code) and code[j] == "{":
        close = match_close(code, j)
        if close > 0:
            return j, close
    return None


def _emit_object_keys(src: Source, acc: Acc, code: str, obj: tuple[int, int], table: str) -> None:
    for off, part in split_top(code[obj[0] + 1:obj[1]]):
        km = re.match(r"""\s*(?:'([\w$]+)'|"([\w$]+)"|([A-Za-z_$][\w$]*))\s*:""", part)
        if km:
            gi = 1 if km.group(1) else 2 if km.group(2) else 3
            add_model_field(acc, src, obj[0] + 1 + off + km.start(gi), table, km.group(gi))


def x_js_models(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    for m in re.finditer(r"""(?:(?:const|let|var)\s+(\w+)\s*=\s*)?new\s+(?:mongoose\.|Mongoose\.)?Schema\s*\(\s*""", code):
        obj = _object_after(code, m.end())
        if obj:
            _emit_object_keys(src, acc, code, obj, re.sub(r"Schema$", "", m.group(1) or "schema") or "schema")
    for m in re.finditer(r"""\.define\s*\(\s*['"](\w+)['"]\s*,\s*""", code):
        obj = _object_after(code, m.end())
        if obj:
            _emit_object_keys(src, acc, code, obj, m.group(1))
    for m in re.finditer(r"""\b(\w+)\.init\s*\(\s*""", code):
        obj = _object_after(code, m.end())
        if obj and re.search(r"DataTypes|Sequelize", code[obj[0]:obj[1]]):
            _emit_object_keys(src, acc, code, obj, m.group(1))
    for m in re.finditer(r"@Entity\s*\([^)]*\)\s*(?:export\s+)?(?:default\s+)?class\s+(\w+)[^{]*\{", code):
        close = match_close(code, m.end() - 1)
        if close < 0:
            continue
        body = code[m.end():close]
        for cm in re.finditer(r"@(?:\w*Column)\s*\([^)]*\)\s*(?:(?:public|private|protected|readonly)\s+)*(\w+)\s*[!?]?\s*[:;=]", body):
            add_model_field(acc, src, m.end() + cm.start(1), m.group(1), cm.group(1))
    for m in re.finditer(r"""\b(?:z|zod|yup|Joi)\.object\s*\(\s*""", code):
        obj = _object_after(code, m.end())
        if not obj:
            continue
        for key, _val in object_keys(code[obj[0] + 1:obj[1]]):
            res = classify(key) if not key.isupper() else None          # SCREAMING_CASE keys are env-var schemas
            if res:
                add_request_field(acc, src, obj[0], f"request.{key}", res, "api-body")


def _columns_after_markers(src: Source, acc: Acc, marks: list[tuple[int, str]], col_re: re.Pattern[str]) -> None:
    if not marks:
        return
    marks = sorted(marks)
    starts = [m[0] for m in marks]
    for cm in col_re.finditer(src.code):
        i = bisect.bisect_right(starts, cm.start()) - 1
        col = next((g for g in cm.groups() if g), None)
        if i >= 0 and col:
            add_model_field(acc, src, cm.start(), marks[i][1], col)


def x_generic_models(src: Source, acc: Acc, ctx: Ctx) -> None:
    """Go / Rust / Kotlin / Java / C# / Ruby / PHP schema-ish definitions (declared fields only)."""
    code = src.code
    ext = Path(src.rel).suffix.lower()
    if ext == ".go":
        for m in re.finditer(r"\btype\s+(\w+)\s+struct\s*\{", code):
            close = match_close(code, m.end() - 1)
            if close < 0:
                continue
            for lm in re.finditer(r"^[ \t]*(\w+)\s+[\w\[\]\*\.]+\s+`[^`\n]*?(?:json|db|bson|gorm|form)\s*:\s*\"([^\",]*)", code[m.end():close], re.M):
                add_model_field(acc, src, m.end() + lm.start(1), m.group(1), lm.group(2) or lm.group(1))
    elif ext == ".rs":
        for m in re.finditer(r"\bstruct\s+(\w+)\s*\{", code):
            close = match_close(code, m.end() - 1)
            if close < 0:
                continue
            for lm in re.finditer(r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(\w+)\s*:\s*[\w<>:&'\[\], ]+,?\s*$", code[m.end():close], re.M):
                add_model_field(acc, src, m.end() + lm.start(1), m.group(1), lm.group(1))
    elif ext in (".kt", ".kts"):
        for m in re.finditer(r"\bdata\s+class\s+(\w+)\s*\(", code):
            args, _close = call_args(code, m.end() - 1)
            for off, txt in args:
                fm = re.match(r"\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:private\s+|public\s+)?(?:val|var)\s+(\w+)\s*:", txt)
                if fm:
                    add_model_field(acc, src, off + fm.start(1), m.group(1), fm.group(1))
    elif ext == ".java":
        for m in re.finditer(r"\b(?:class|record)\s+(\w+)[^{;(]*[{(]", code):
            if code[m.end() - 1] == "(":
                args, _close = call_args(code, m.end() - 1)
                for off, txt in args:
                    fm = re.match(r"\s*(?:@\w+(?:\([^)]*\))?\s*)*[\w<>\[\],.? ]+\s+(\w+)\s*$", txt)
                    if fm:
                        add_model_field(acc, src, off + fm.start(1), m.group(1), fm.group(1))
                continue
            close = match_close(code, m.end() - 1)
            if close < 0:
                continue
            for fm in re.finditer(r"^[ \t]*(?:@\w+(?:\([^)]*\))?\s*)*(?:private|protected|public)\s+(?:final\s+)?[\w<>\[\],.? ]+\s+(\w+)\s*(?:=[^;]*)?;", code[m.end():close], re.M):
                add_model_field(acc, src, m.end() + fm.start(1), m.group(1), fm.group(1))
    elif ext == ".cs":
        for m in re.finditer(r"\b(?:class|record)\s+(\w+)[^{;(]*\{", code):
            close = match_close(code, m.end() - 1)
            if close < 0:
                continue
            for fm in re.finditer(r"^[ \t]*public\s+[\w<>\[\],.?]+\s+(\w+)\s*\{\s*get\s*;", code[m.end():close], re.M):
                add_model_field(acc, src, m.end() + fm.start(1), m.group(1), fm.group(1))
    elif ext == ".rb":
        marks = [(m.start(), m.group(1)) for m in re.finditer(r"""\bcreate_table\s+[:"'](\w+)""", code)]
        _columns_after_markers(src, acc, marks, re.compile(r"""\bt\.\w+\s+[:"'](\w+)"""))
    elif ext == ".php":
        marks = [(m.start(), m.group(1)) for m in re.finditer(r"""Schema::create\(\s*['"](\w+)['"]""", code)]
        _columns_after_markers(src, acc, marks, re.compile(r"""\$table->\w+\(\s*['"](\w+)['"]"""))


# --------------------------------------------------------------------------- Python (AST)

_ROUTE_DECOS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "route", "api_route", "websocket", "api_view"})
_PYDANTIC_BASES = frozenset({"BaseModel", "SQLModel", "Schema", "TypedDict", "NamedTuple", "Struct"})
_ORM_BASES = frozenset({"Model", "Base", "DeclarativeBase", "DeclarativeBaseNoMeta", "Document", "EmbeddedDocument"})
_COLUMN_FUNCS = frozenset({"Column", "mapped_column"})
_ANALYTICS_FN_RE = re.compile(r"^(track|capture|identify|track_event|trackEvent|log_event|logEvent|send_event|sendEvent|emit_event|report_event|analytics_\w+)$")
_SKIP_ARGS = frozenset({"self", "cls", "request", "response", "background_tasks", "db", "session", "websocket", "req", "res"})
_SKIP_ANN = re.compile(r"\b(Request|Response|BackgroundTasks|WebSocket|Session|AsyncSession|HTTPConnection)\b")
_TYPING_NAMES = frozenset({"Optional", "List", "Dict", "Any", "Union", "Annotated", "Literal", "Set", "Tuple", "UploadFile", "Sequence"})
_PARAM_MARKERS = frozenset({"Form", "Header", "Cookie", "Query", "File", "Body", "Depends", "Security", "Path"})


def _name_of(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    if isinstance(node, ast.Subscript):
        return _name_of(node.value)
    return None


def _value_word(node: ast.AST | None) -> str | None:
    """Best identifier describing an expression: row["email"] -> email, user.email -> email."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Subscript):
        sl = node.slice
        if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
            return sl.value
        return _value_word(node.value)
    if isinstance(node, ast.Call):
        return _value_word(node.func)
    return None


def _is_route(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, (ast.Attribute, ast.Name)) and (_name_of(target) in _ROUTE_DECOS):
            return True
    return False


def _fn_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[ast.arg, ast.AST | None]]:
    a = fn.args
    pos = list(a.posonlyargs) + list(a.args)
    defaults: list[ast.AST | None] = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
    return list(zip(pos, defaults)) + list(zip(a.kwonlyargs, a.kw_defaults))


def x_python(src: Source, acc: Acc, ctx: Ctx) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            tree = ast.parse(src.raw)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            acc.warnings.append(f"could not parse Python: {src.rel}")
            return
    classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}

    def model_kind(cls: ast.ClassDef, seen: frozenset[str] = frozenset()) -> str | None:
        if any(_name_of(d) in ("dataclass", "define", "frozen") for d in cls.decorator_list):
            return "dataclass"
        for b in (x for x in (_name_of(b) for b in cls.bases) if x):
            if b in _PYDANTIC_BASES:
                return "pydantic"
            if b in _ORM_BASES:
                return "orm"
            if b in classes and b not in seen and b != cls.name:
                k = model_kind(classes[b], seen | {cls.name})
                if k:
                    return k
            if b.endswith(("Model", "Document")):
                return "orm"
            if b.endswith("Schema"):
                return "pydantic"
        return None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_route(node):
                _py_route(src, acc, node)
        elif isinstance(node, ast.ClassDef):
            kind = model_kind(node)
            if kind:
                _py_class(src, acc, node, kind)
        elif isinstance(node, ast.Call):
            _py_call(src, acc, ctx, node)


def _py_class(src: Source, acc: Acc, cls: ast.ClassDef, kind: str) -> None:
    table = cls.name
    for st in cls.body:
        if isinstance(st, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__tablename__" for t in st.targets):
            if isinstance(st.value, ast.Constant) and isinstance(st.value.value, str):
                table = st.value.value
    for st in cls.body:
        col: str | None = None
        override: str | None = None
        if isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
            col = st.target.id
            ann = ast.unparse(st.annotation)
            if "ClassVar" in ann:
                continue
            override = classify_type(ann)
        elif isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Name) \
                and isinstance(st.value, ast.Call):
            fname = _name_of(st.value.func) or ""
            if fname in _COLUMN_FUNCS or fname.endswith("Field"):
                col = st.targets[0].id
                override = classify_type(fname)
        if not col or col.startswith("_") or col in ("model_config", "Config", "Meta"):
            continue
        res = classify(col, table)
        if override and (res is None or res[0] in ("content", "other", "identifier")):
            res = (override, None)
        ref = f"{src.rel}:{st.lineno}"
        if res is None:
            if len(acc.unclassified) < 500:
                acc.unclassified.append({"name": f"{table}.{col}", "ref": ref})
            continue
        acc.pending_py.append({"cls_name": cls.name, "kind": kind, "name": f"{table}.{col}", "res": res, "ref": ref})


def _py_route(src: Source, acc: Acc, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
    for arg, default in _fn_params(fn):
        ann_node = arg.annotation
        ann = ast.unparse(ann_node) if ann_node is not None else ""
        ann_names = [n.id for n in ast.walk(ann_node) if isinstance(n, ast.Name)] if ann_node is not None else []
        for n in ann_names:
            if n[:1].isupper() and n not in _TYPING_NAMES:
                acc.request_models.add(n)
        markers = {_name_of(default)} if isinstance(default, ast.Call) else set()
        if ann_node is not None:                       # Annotated[str, Form()]
            markers |= {_name_of(n) for n in ast.walk(ann_node) if isinstance(n, ast.Call)}
        markers &= _PARAM_MARKERS
        if arg.arg in _SKIP_ARGS or _SKIP_ANN.search(ann) or markers & {"Depends", "Security"}:
            continue
        ref = f"{src.rel}:{arg.lineno}"
        if "UploadFile" in ann or "File" in markers:
            acc.add_field(f"upload.{arg.arg}", "content", "api-body", ref)
            continue
        if not markers and ann_names[:1] and ann_names[0][:1].isupper() and ann_names[0] not in _TYPING_NAMES:
            continue                                   # a request-model parameter: its fields are recorded on the class
        res = classify(arg.arg)
        if res is None and classify_type(ann):
            res = (classify_type(ann), None)  # type: ignore[assignment]
        if res is None:
            continue
        if "Form" in markers:
            name, via = f"form.{arg.arg}", "form"
        elif "Header" in markers:
            name, via = f"request.header.{arg.arg}", "api-body"
        elif "Cookie" in markers:
            name, via = f"cookie.{arg.arg}", "cookie"
        elif "Query" in markers:
            name, via = f"request.query.{arg.arg}", "api-body"
        else:
            name, via = f"request.{arg.arg}", "api-body"
        acc.add_field(name, res[0], via, ref, kind=res[1])


def _dict_pairs(d: ast.Dict) -> list[tuple[str, ast.AST | None]]:
    return [(k.value, v) for k, v in zip(d.keys, d.values) if isinstance(k, ast.Constant) and isinstance(k.value, str)]


def _py_call(src: Source, acc: Acc, ctx: Ctx, call: ast.Call) -> None:
    fname = _name_of(call.func)
    if not fname:
        return
    if _ANALYTICS_FN_RE.match(fname):                  # track("login", user_id=..., email=row["email"])
        event = None
        for a in call.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str):
                event = a.value
                break
        for kw in call.keywords:
            if kw.arg in ("event", "event_name") and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                event = kw.value.value
        pairs: list[tuple[str, ast.AST | None]] = []
        for kw in call.keywords:
            if kw.arg and kw.arg not in ("event", "event_name", "distinct_id", "timestamp"):
                if kw.arg in ("properties", "props", "traits", "payload", "data") and isinstance(kw.value, ast.Dict):
                    pairs.extend(_dict_pairs(kw.value))
                else:
                    pairs.append((kw.arg, kw.value))
        for a in call.args:
            if isinstance(a, ast.Dict):
                pairs.extend(_dict_pairs(a))
        ev = re.sub(r"[^\w-]+", "_", event or fname) or "event"
        found = False
        for key, val in pairs:
            res = classify(key) or (classify(_value_word(val) or "") if val is not None else None)
            if res:
                acc.add_field(f"analytics.{ev}.{key}", res[0], "analytics-event", f"{src.rel}:{call.lineno}", kind=res[1], usage=False)
                acc.event_file(src.rel)["fields"].add(f"analytics.{ev}.{key}")
                found = True
        if found or event:
            ctx.mark_event_file(src, acc)
    if fname == "set_cookie":                          # response.set_cookie("name", ..., max_age=...)
        name = None
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            name = call.args[0].value
        for kw in call.keywords:
            if kw.arg == "key" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                name = kw.value.value
        if name:
            exp = next((f"{kw.arg}={ast.unparse(kw.value)}" for kw in call.keywords if kw.arg in ("max_age", "expires")), None)
            acc.add_storage("cookie", name, f"{src.rel}:{call.lineno}", expiry=exp or "session (no max_age/expires set)",
                            necessity=_client_storage_necessity(name))


def x_py_regex(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    for m in re.finditer(r"""\brequest\.(form|json|values|POST|data|args|GET|cookies|files)(?:\.get(?:list)?\(|\[)\s*['"]([\w-]+)['"]""", code):
        kind, key = m.group(1), m.group(2)
        if kind == "files":
            acc.add_field(f"upload.{key}", "content", "api-body", src.ref(m.start()))
            continue
        res = classify(key)
        if res:
            via = {"form": "form", "POST": "form", "cookies": "cookie"}.get(kind, "api-body")
            prefix = {"form": "form", "POST": "form", "cookies": "cookie", "args": "request.query", "GET": "request.query"}.get(kind, "request")
            add_request_field(acc, src, m.start(), f"{prefix}.{key}", res, via)
    marks = [(m.start(), m.group(1)) for m in re.finditer(r"""\bcreate_table\(\s*['"](\w+)['"]""", code)]
    marks += [(m.start(), m.group(1)) for m in re.finditer(r"""\bCreateModel\(\s*name=['"](\w+)['"]""", code)]
    marks += [(m.start(), m.group(1)) for m in re.finditer(r"""\badd_column\(\s*['"](\w+)['"]""", code)]
    _columns_after_markers(src, acc, marks, re.compile(r"""\bColumn\(\s*['"](\w+)['"]|\(\s*['"](\w+)['"]\s*,\s*models\.\w+"""))
    for m in re.finditer(r"\bSessionMiddleware\b", code):
        if re.search(r"add_middleware|Middleware\(", code[max(0, m.start() - 40):m.end() + 20]):
            seg = code[m.end():m.end() + 300]
            nm = re.search(r"""session_cookie\s*=\s*['"]([^'"]+)['"]""", seg)
            ma = re.search(r"max_age\s*=\s*([^,)\n]+)", seg)
            acc.add_storage("cookie", nm.group(1) if nm else "session", src.ref(m.start()),
                            expiry=f"max_age={ma.group(1).strip()}" if ma else "framework default", necessity="strictly-necessary")
    if re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b", code):
        for m in re.finditer(r"\bsession\s*\[[^\]]+\]\s*=", code):
            acc.add_storage("cookie", "session", src.ref(m.start()), expiry="session (framework default)", necessity="strictly-necessary")


# --------------------------------------------------------------------------- JS / TS / HTML extractors

_REQ = r"(?:req|request|ctx\.request)"
_BODY_PROP_RE = re.compile(_REQ + r"\.body\.([A-Za-z_$][\w$]*)")
_BODY_IDX_RE = re.compile(_REQ + r"""\.body\[\s*['"]([\w$-]+)['"]\s*\]""")
_BODY_PAREN_RE = re.compile(r"\(\s*" + _REQ + r"\.body\s*(?:\|\||\?\?)\s*\{\s*\}\s*\)\.([A-Za-z_$][\w$]*)")
_QUERY_PROP_RE = re.compile(_REQ + r"\.(query|params|cookies)\.([A-Za-z_$][\w$]*)")
_QUERY_IDX_RE = re.compile(_REQ + r"""\.(query|params|cookies)\[\s*['"]([\w$-]+)['"]\s*\]""")
_HEADER_RE = re.compile(_REQ + r"""\.(?:get|header)\(\s*['"]([\w-]+)['"]\s*\)|""" + _REQ + r"""\.headers(?:\.([A-Za-z_$][\w$]*)|\[\s*['"]([\w-]+)['"]\s*\])""")
_IP_RE = re.compile(_REQ + r"\.(?:ip|ips)\b|\b(?:connection|socket)\.remoteAddress\b")
_DESTRUCT_RE = re.compile(
    r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?(?:" + _REQ + r"\.(?P<kind>body|query|params|cookies)|" + _REQ + r"\.(?:json|formData)\(\))")
_FORMDATA_RE = re.compile(r"""\b(?:formData|form_data|fd)\.(?:get|getAll)\(\s*['"]([\w-]+)['"]\s*\)""")


def x_js_requests(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    for rx in (_BODY_PROP_RE, _BODY_IDX_RE, _BODY_PAREN_RE):
        for m in rx.finditer(code):
            res = classify(m.group(1))
            if res:
                add_request_field(acc, src, m.start(), f"request.{m.group(1)}", res, "api-body")
    for rx in (_QUERY_PROP_RE, _QUERY_IDX_RE):
        for m in rx.finditer(code):
            res = classify(m.group(2))
            if res:
                if m.group(1) == "cookies":
                    add_request_field(acc, src, m.start(), f"cookie.{m.group(2)}", res, "cookie")
                else:
                    add_request_field(acc, src, m.start(), f"request.{m.group(1)}.{m.group(2)}", res, "api-body")
    for m in _HEADER_RE.finditer(code):
        h = m.group(1) or m.group(2) or m.group(3)
        res = classify(h) if h else None
        if res:
            add_request_field(acc, src, m.start(), f"request.header.{h.lower()}", res, "api-body")
    for m in _IP_RE.finditer(code):
        acc.add_field("request.ip", "location", "api-body", src.ref(m.start()), usage=False)
    for m in _DESTRUCT_RE.finditer(code):
        kind = m.group("kind") or "body"
        for _, part in split_top(m.group(1)):
            part = part.strip()
            if not part or part.startswith("..."):
                continue
            key = re.split(r"[:=]", part, maxsplit=1)[0].strip()
            res = classify(key) if re.fullmatch(r"[A-Za-z_$][\w$]*", key) else None
            if not res:
                continue
            if kind == "cookies":
                add_request_field(acc, src, m.start(), f"cookie.{key}", res, "cookie")
            elif kind in ("query", "params"):
                add_request_field(acc, src, m.start(), f"request.{kind}.{key}", res, "api-body")
            else:
                add_request_field(acc, src, m.start(), f"request.{key}", res, "api-body")
    for m in _FORMDATA_RE.finditer(code):
        res = classify(m.group(1))
        if res:
            add_request_field(acc, src, m.start(), f"form.{m.group(1)}", res, "form")


_JS_ANALYTICS_RE = re.compile(
    r"(?<![\w$.])(?:(?:window\.|this\.|self\.)?(?:analytics|segment|mixpanel|amplitude|posthog|heap|rudderanalytics|ga|\$analytics|plausible)"
    r"\.(?:track|capture|logEvent|identify|event|send|trackEvent|trackCustom)|dataLayer\.push|gtag|fbq|plausible|track|trackEvent|"
    r"logEvent|captureEvent|sendEvent|logAnalytics)\s*\(")


_CALLEE_VENDOR = {"gtag": "Google Analytics / Tag Manager", "dataLayer": "Google Analytics / Tag Manager", "fbq": "Meta (Facebook)",
                  "mixpanel": "Mixpanel", "amplitude": "Amplitude", "posthog": "PostHog", "segment": "Segment", "heap": "Heap",
                  "plausible": "Plausible"}


def x_js_analytics(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    for m in _JS_ANALYTICS_RE.finditer(code):
        if re.search(r"(?:function|async|def|class)\s+$", code[max(0, m.start() - 12):m.start()]):
            continue                                     # a definition, not a call
        args, close = call_args(code, m.end() - 1)
        if close < 0:
            continue
        callee = m.group(0)
        texts = [t for _, t in args]
        lits = [str_literal(t) for t in texts]
        event = None
        if callee.startswith("gtag") and lits and lits[0] == "event":
            event = lits[1] if len(lits) > 1 else None
        elif callee.startswith("fbq") and lits and lits[0] in ("track", "trackCustom"):
            event = lits[1] if len(lits) > 1 else None
        elif not callee.startswith("dataLayer"):
            event = next((s for s in lits if s), None)
        pairs: list[tuple[str, str]] = []
        for t in texts:
            t = t.strip()
            if t.startswith("{"):
                inner_close = match_close(t, 0)
                if inner_close > 0:
                    pairs.extend(object_keys(t[1:inner_close]))
        if callee.startswith("dataLayer"):
            event = next((str_literal(v) for k, v in pairs if k == "event" and str_literal(v)), None)
        ev = re.sub(r"[^\w-]+", "_", event or "event") or "event"
        found = False
        for key, val in pairs:
            if key == "event" or val.startswith("{"):
                continue
            res = classify(key)
            if not res:
                words = _IDENT_RE.findall(val)
                res = classify(words[-1]) if words else None
            if res:
                name = f"analytics.{ev}.{key}"
                acc.add_field(name, res[0], "analytics-event", src.ref(m.start()), kind=res[1], usage=False)
                acc.event_file(src.rel)["fields"].add(name)
                found = True
        if found or event:
            ctx.mark_event_file(src, acc)
            base = re.sub(r"^(?:window|this|self)\.", "", callee).split(".")[0].split("(")[0].strip()
            if base in _CALLEE_VENDOR:
                acc.event_file(src.rel)["vendors"].add(_CALLEE_VENDOR[base])


_HTML_INPUT_RE = re.compile(r"""<(input|textarea|select)\b((?:[^>"']|"[^"]*"|'[^']*')*)>""", re.I)
_ATTR_RE = re.compile(r"""([\w:@.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{\s*["']([^"']*)["']\s*\}|([^\s>]+))""")
_FORM_RE = re.compile(r"""<form\b((?:[^>"']|"[^"]*"|'[^']*')*)>(.*?)</form\s*>""", re.I | re.S)
_INPUT_TYPE_CLS = {"email": "contact", "tel": "contact", "password": "credential", "file": "content"}
_INPUT_SKIP_TYPES = frozenset({"submit", "button", "reset", "image", "checkbox", "radio", "range", "color"})


def _attrs(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in _ATTR_RE.finditer(text):
        out[m.group(1).lower()] = next(g for g in m.groups()[1:] if g is not None)
    return out


def x_html(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    if "<" not in code:
        return
    positions: list[tuple[int, str]] = []
    for m in _HTML_INPUT_RE.finditer(code):
        attrs = _attrs(m.group(2))
        name = attrs.get("name") or attrs.get("formcontrolname") or attrs.get("v-model") or attrs.get("ng-model")
        itype = attrs.get("type", "text" if m.group(1).lower() == "input" else m.group(1).lower()).lower()
        if itype in _INPUT_SKIP_TYPES or not name or re.search(r"csrf|xsrf|authenticity", name, re.I):
            continue
        name = name.split(".")[-1]
        res = classify(name)
        if (res is None or res[0] in ("content", "other")) and itype in _INPUT_TYPE_CLS:
            res = (_INPUT_TYPE_CLS[itype], None)
        ac = attrs.get("autocomplete", "").split(" ")[-1]
        if res is None and ac in _AUTOCOMPLETE:
            res = (_AUTOCOMPLETE[ac], None)
        if res is None:
            continue
        full = f"form.{name}"
        acc.add_field(full, res[0], "form", src.ref(m.start()), kind=res[1])
        positions.append((m.start(), full))
    for fm in _FORM_RE.finditer(code):
        hm = re.match(r"(?:https?:)?//([^/\s:?#]+)(?::(\d+))?", _attrs(fm.group(1)).get("action", ""))
        if not hm:
            continue
        key = _register_host(acc, ctx, src, fm.start(), hm.group(1), hm.group(2), force=True, note="HTML form posts to this host")
        if key:
            acc.third[key]["data_sent"].update(n for pos, n in positions if fm.start(2) <= pos <= fm.end(2))


def _client_storage_necessity(name: str) -> str:
    n = name.lower()
    if re.search(r"^_fbp|^_fbc|^fr$|^ide$|^test_cookie|doubleclick|^_gcl|adroll|advert|^_uet|^muid|criteo|^_scid|^_ttp", n):
        return "advertising"
    if re.search(r"^_ga|^_gid|^_gat|^_hj|^ajs_|^mp_|^ph_|^amp_|^_pk_|^__utm|^_clck|^_clsk|^_fs_uid|plausible|matomo|^_trk|^trk_|tracker|tracking", n):
        return "analytics"
    if re.search(r"consent|cookie.?(?:banner|notice|choice)|csrf|xsrf|sess|^sid$|^sid[_.-]|auth|jwt|login|^token|_token$|^connect\.sid|cart|checkout|load.?balanc", n):
        return "strictly-necessary"
    if re.search(r"analytic|visitor|telemetry", n):
        return "analytics"
    if re.search(r"theme|lang|locale|i18n|pref|setting|dark|mode|timezone|remember|layout|font|currency|region", n):
        return "functional"
    return "unknown"


def _resolve_const(code: str, name: str) -> str | None:
    m = re.search(r"""\b(?:const|let|var)\s+""" + re.escape(name) + r"""\s*=\s*['"]([^'"]+)['"]""", code) or \
        re.search(r"(?m)^[ \t]*" + re.escape(name) + r"""\s*=\s*['"]([^'"]+)['"]""", code)
    return m.group(1) if m else None


_COOKIE_OPT_RE = re.compile(r"\b(maxAge|expires|max_age)\b\s*[:=]\s*([^,}\n)]+)", re.I)


def _cookie_expiry(text: str) -> str:
    parts = [f"{m.group(1)}={m.group(2).strip()}" for m in _COOKIE_OPT_RE.finditer(text)]
    return ", ".join(parts) if parts else "session (no maxAge/expires set)"


def _name_or_dynamic(code: str, expr: str) -> str:
    expr = expr.strip()
    if expr.startswith("{"):                                       # cookies.set({ name: 'x', value }) style
        nm = re.search(r"""\bname\s*:\s*(?:['"]([^'"]+)['"]|([A-Za-z_$][\w$.]*))""", expr)
        if nm and nm.group(1):
            return nm.group(1)
        return "<dynamic: cookie options object>"
    lit = str_literal(expr)
    if lit is not None:
        return lit
    resolved = _resolve_const(code, expr) if re.fullmatch(r"[A-Za-z_$][\w$.]*", expr) else None
    return resolved or f"<dynamic: {expr[:40]}>"


def x_js_storage(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    for m in re.finditer(r"\b(local|session)Storage\.setItem\s*\(", code):
        args, _close = call_args(code, m.end() - 1)
        if args:
            name = _name_or_dynamic(code, args[0][1])
            acc.add_storage(f"{m.group(1)}Storage", name, src.ref(m.start()), necessity=_client_storage_necessity(name))
    for m in re.finditer(r"""\b(local|session)Storage\[\s*(['"`])([^'"`]+)\2\s*\]\s*=(?!=)""", code):
        acc.add_storage(f"{m.group(1)}Storage", m.group(3), src.ref(m.start()), necessity=_client_storage_necessity(m.group(3)))
    for m in re.finditer(r"\b(local|session)Storage\.(?!setItem|getItem|removeItem|clear|key|length)(\w+)\s*=(?!=)", code):
        acc.add_storage(f"{m.group(1)}Storage", m.group(2), src.ref(m.start()), necessity=_client_storage_necessity(m.group(2)))
    for m in re.finditer(r"""\b(?:indexedDB\.open|openDB|new\s+Dexie)\s*\(\s*['"`]([^'"`]+)['"`]""", code):
        acc.add_storage("indexedDB", m.group(1), src.ref(m.start()), necessity=_client_storage_necessity(m.group(1)))
    for m in re.finditer(r"\b(?:res|response|reply|ctx)\.cookie\s*\(|\b(?:Cookies|cookies|cookie|jsCookie)\.set\s*\(|\bsetCookie\s*\(", code):
        args, _close = call_args(code, m.end() - 1)
        if args:
            name = _name_or_dynamic(code, args[0][1])
            acc.add_storage("cookie", name, src.ref(m.start()), expiry=_cookie_expiry(" ".join(t for _, t in args[2:])),
                            necessity=_client_storage_necessity(name))
    for m in re.finditer(r"""\bdocument\.cookie\s*=\s*(['"`])\s*([^=;'"`$\s]+)\s*=([^'"`]*)""", code):
        acc.add_storage("cookie", m.group(2), src.ref(m.start()), expiry=_cookie_expiry(m.group(3)),
                        necessity=_client_storage_necessity(m.group(2)))
    for m in re.finditer(r"\b(session|cookieSession)\s*\(\s*\{", code):       # express-session / cookie-session
        close = match_close(code, m.end() - 1)
        if close < 0:
            continue
        body = code[m.end() - 1:close]
        if m.group(1) == "session" and not re.search(r"express-session|secret\s*:", code):
            continue
        nm = re.search(r"""\bname\s*:\s*['"]([^'"]+)['"]""", body)
        acc.add_storage("cookie", nm.group(1) if nm else ("connect.sid" if m.group(1) == "session" else "session"),
                        src.ref(m.start()), expiry=_cookie_expiry(body), necessity="strictly-necessary",
                        note="session cookie created by session middleware")


_SET_COOKIE_RE = re.compile(r"""['"]set-cookie['"]\s*[,:\]=]\s*[\[(]?\s*[fF`]?(['"`])\s*([^=;'"`{$%\s]+)=([^'"`]*)""", re.I)


def x_set_cookie_header(src: Source, acc: Acc, ctx: Ctx) -> None:
    for m in _SET_COOKIE_RE.finditer(src.code):
        em = re.search(r"(?i)\b(max-age|expires)\s*=\s*([^;'\"`]+)", m.group(3))
        acc.add_storage("cookie", m.group(2), src.ref(m.start()),
                        expiry=f"{em.group(1)}={em.group(2).strip()}" if em else "session (no Max-Age/Expires set)",
                        necessity=_client_storage_necessity(m.group(2)))


# --------------------------------------------------------------------------- hosts / third parties

_URL_RE = re.compile(
    r"""(?<![\w.-])(?:https?|wss?)://(?:[^\s/@"'`<>]+@)?(?P<host>\[[0-9a-fA-F:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?)(?::(?P<port>\d{1,5}|\$?\{\w+\}))?(?P<path>[/?#][^\s"'`<>)\\]*)?""",
    re.I)
_PROTO_REL_RE = re.compile(r"""\b(?:src|href|action|data-src|poster)\s*=\s*["']?//([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})""", re.I)
_DB_URL_RE = re.compile(r"""\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://(?:[^\s/@"'`<>]*@)?([A-Za-z0-9][A-Za-z0-9.\-]*)""", re.I)
_IGNORED_HOST_RE = re.compile(
    r"(^|\.)(w3\.org|schema\.org|json-schema\.org|xmlsoap\.org|example\.(com|org|net)|iana\.org|ietf\.org|rfc-editor\.org|"
    r"mozilla\.org|wikipedia\.org|npmjs\.(org|com)|readthedocs\.io|creativecommons\.org|gnu\.org|apache\.org|opensource\.org|"
    r"python\.org|nodejs\.org|stackoverflow\.com|spdx\.org|ogp\.me|purl\.org|openxmlformats\.org|xmlns\.com|"
    r"pypi\.org|pythonhosted\.org|yarnpkg\.com|github\.io|gitlab\.io)$|"
    r"\.(test|invalid|example|localhost|local|internal|lan|home|corp)$|"
    r"^(www\.)?(your|my)[-_]?(domain|site|app|company|website|server|host)\.|^(www\.)?(domain|mysite|yoursite|site)\.(com|org|net)$|"
    r"^[a-z0-9-]*example[a-z0-9-]*\.(com|org|net)$", re.I)
_LOOPBACK_RE = re.compile(r"^(localhost|0\.0\.0\.0|\[?::1\]?|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$", re.I)
_ANALYTICS_HINT_RE = re.compile(r"analytic|track|telemetry|collect|beacon|pixel|sentry|metrics", re.I)


def _ignored_host(host: str) -> bool:
    return bool(_IGNORED_HOST_RE.search(host)) or any(c in host for c in "%{$")


def _host_key(host: str, port: str | None) -> str:
    host = host.lower()
    if _LOOPBACK_RE.match(host) and port and port.isdigit():
        return f"{host}:{port}"
    return host


def _vendor_for(host: str) -> tuple[str, str, str] | None:
    for rx, vendor, purpose, cat in VENDOR_HOSTS:
        if rx.search(host):
            return vendor, purpose, cat
    return None


def _register_host(acc: Acc, ctx: Ctx, src: Source, idx: int, host: str, port: str | None, *, force: bool = False,
                   note: str | None = None, url_path: str = "", var_name: str | None = None) -> str | None:
    host = host.lower()
    if _ignored_host(host):
        return None
    loop = bool(_LOOPBACK_RE.match(host))
    before = src.code[max(src.line_start(idx), idx - 40):idx]      # what the URL is called, not the whole line
    hinted = bool(_ANALYTICS_HINT_RE.search(before) or _ANALYTICS_HINT_RE.search(url_path))
    if loop and not (hinted or force):
        return None
    if not loop and "." not in host:
        return None
    if port and not port.isdigit():
        name = port.strip("${}")
        port = ctx.const_int(src, name) if name.isidentifier() else None
    key = _host_key(host, port)
    vendor = _vendor_for(host)
    kwargs: dict[str, Any] = {}
    if vendor:
        kwargs.update(vendor=vendor[0], purpose=vendor[1], category=vendor[2])
    elif loop and hinted:
        kwargs.update(purpose="analytics / telemetry (inferred from the endpoint name)", category="analytics")
        note = (note + "; " if note else "") + ("loopback/private host listed because it looks like an analytics endpoint "
                                                "(possibly a local stand-in for a vendor)")
    acc.add_third(key, src.ref(idx), note=note, analytics_like=bool((vendor and vendor[2] in ANALYTICS_CATEGORIES) or hinted), **kwargs)
    ctx.file_hosts.setdefault(src.rel, set()).add(key)
    if src.rel in acc.event_files:
        acc.event_files[src.rel]["hosts"].add(key)
    if var_name:
        acc.url_vars[var_name] = key
    return key


_ASSIGN_TAIL_RE = re.compile(r"""([A-Za-z_]\w*)\s*(?::[^=]*)?[:=]\s*[fFrRbB]?['"`]?\s*$""")


def x_hosts(src: Source, acc: Acc, ctx: Ctx) -> None:
    scan = src.code
    if src.kind == "html":          # hyperlinks and page metadata are not data flows: blank them
        scan = re.sub(r"<a\b[^>]*>", lambda m: " " * len(m.group(0)), scan, flags=re.I)
        scan = re.sub(r"<meta\b[^>]*>", lambda m: " " * len(m.group(0)), scan, flags=re.I)
        scan = re.sub(r"<link\b[^>]*>", lambda m: m.group(0) if re.search(
            r"rel\s*=\s*[\"']?(?:stylesheet|preload|prefetch|preconnect|dns-prefetch|modulepreload|icon|manifest)", m.group(0), re.I)
            else " " * len(m.group(0)), scan, flags=re.I)
    for m in _URL_RE.finditer(scan):
        host = m.group("host")
        if host.startswith("["):
            continue
        prefix = scan[src.line_start(m.start()):m.start()]
        vm = _ASSIGN_TAIL_RE.search(prefix)
        _register_host(acc, ctx, src, m.start(), host, m.group("port"), url_path=m.group("path") or "",
                       var_name=vm.group(1) if vm else None)
    for m in _PROTO_REL_RE.finditer(scan):
        _register_host(acc, ctx, src, m.start(), m.group(1), None)
    for m in _DB_URL_RE.finditer(src.code):
        host = m.group(1).lower()
        if not (_LOOPBACK_RE.match(host) or _ignored_host(host) or "." not in host):
            _register_host(acc, ctx, src, m.start(), host, None, force=True, note="database / broker connection host")


def x_sdk_imports(src: Source, acc: Acc, ctx: Ctx) -> None:
    for rx, host, vendor, purpose, cat in SDK_IMPORTS:
        for m in rx.finditer(src.code):
            if not re.search(r"\b(import|require|from)\b", src.line_text(m.start())):
                continue
            acc.add_third(host, src.ref(m.start()), vendor=vendor, purpose=purpose, category=cat,
                          note="SDK import; host inferred from the vendor, data flow not traced",
                          analytics_like=cat in ANALYTICS_CATEGORIES)
            ctx.file_sdk_hosts.setdefault(src.rel, set()).add(host)
            if src.rel in acc.event_files:
                acc.event_files[src.rel]["sdk"].add(host)
            break


# --------------------------------------------------------------------------- stores / log sinks / rights

def _resolve_path_expr(expr: str, code: str, depth: int = 0) -> list[str]:
    parts: list[str] = []
    for m in re.finditer(r"""[fFrRbB]{0,2}(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|`((?:\\.|[^`\\])*)`)|([A-Za-z_$][\w$]*)""", expr):
        lit = m.group(1) or m.group(2) or m.group(3)
        if lit is not None:
            if lit not in ("..", "."):
                parts.append(lit)
        elif m.group(4) and depth < 3 and m.group(4) not in {
                "os", "path", "join", "dirname", "__file__", "__dirname", "process", "cwd", "Path", "resolve", "abspath",
                "True", "False", "None", "mode", "filename", "str", "String"}:
            am = re.search(r"(?m)^[ \t]*(?:const|let|var|final)?[ \t]*" + re.escape(m.group(4)) + r"\s*(?::[^=\n]+)?=\s*([^\n;]+)", code)
            if am:
                parts.extend(_resolve_path_expr(am.group(1), code, depth + 1))
    return parts


def _plausible_path_expr(expr: str) -> bool:
    return not any(t in expr for t in ("=>", ";", "{", "}", "\n"))


def _add_file_store(acc: Acc, src: Source, idx: int, expr: str, note: str | None = None) -> None:
    if _plausible_path_expr(expr):
        acc.add_store("file", _file_name(expr, src.code), src.ref(idx), note=note)


def _file_name(expr: str, code: str) -> str:
    parts = [p for p in _resolve_path_expr(expr, code) if not p.startswith(("{", "$")) and p not in ("a", "w", "wb", "ab", "utf8", "utf-8")]
    if parts:
        return "/".join(p.strip("/") for p in parts)[:80]
    return f"file ({expr.strip()[:40]})"


def x_stores(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    in_memory = ":memory:" in code
    for ln, line in enumerate(code.split("\n"), 1):
        if line.strip() and IMPORTISH_RE.search(line):
            for rx, kind, name in STORE_PATTERNS:
                if rx.search(line):
                    acc.add_store(kind, f"{name} (in-memory)" if name == "sqlite" and in_memory else name, f"{src.rel}:{ln}")
    for m in re.finditer(r"""\bcreate_engine\(\s*f?['"]([a-z]+)""", code):
        name = {"postgresql": "postgresql", "postgres": "postgresql", "mysql": "mysql", "sqlite": "sqlite", "mssql": "sql-server"}.get(m.group(1))
        if name:
            acc.add_store("database", name + (" (in-memory)" if name == "sqlite" and in_memory else ""), src.ref(m.start()))
    for m in FILE_WRITE_JS_RE.finditer(code):
        args, _close = call_args(code, m.end() - 1)
        if args:
            _add_file_store(acc, src, m.start(), args[0][1])
    for m in FILE_HANDLER_RE.finditer(code):
        args, _close = call_args(code, m.end() - 1)
        if args:
            _add_file_store(acc, src, m.start(), args[0][1], "log file")
    for m in PY_OPEN_RE.finditer(code):
        args, _close = call_args(code, m.end() - 1)
        if len(args) >= 2:
            mode = str_literal(args[1][1]) or next((str_literal(t.split("=", 1)[1]) for _, t in args[1:] if t.strip().startswith("mode=")), None)
            if mode and re.fullmatch(r"[wax][bt+]*", mode):
                _add_file_store(acc, src, m.start(), args[0][1])
    for m in WINSTON_FILE_RE.finditer(code):
        if "transports" in code[max(0, m.start() - 80):m.start()] or "File" in code[max(0, m.start() - 80):m.start()]:
            end = re.search(r"[,}\n]", code[m.end():])
            _add_file_store(acc, src, m.start(), code[m.end():m.end() + (end.start() if end else 60)], "log file")
    for m in MULTER_RE.finditer(code):
        args, _close = call_args(code, m.end() - 1)
        dm = re.search(r"""\bdest\s*:\s*([^,}]+)""", args[0][1]) if args else None
        if dm:
            _add_file_store(acc, src, m.start(), dm.group(1), "uploaded files")


_LOG_CALL_RE = re.compile(
    r"(?<![\w$])(?P<callee>(?:[\w$]+\.)*(?:console|logger|log|logging|LOGGER|_log|_logger|Log|slog|winston|pino|bunyan|log4js)\.[A-Za-z]+|"
    r"(?<![.\w$])(?:log|logger|logInfo|logError|logWarn|logMessage|debug|print|println|printf|NSLog|os_log)|fmt\.F?[Pp]rint\w*|System\.out\.print(?:ln)?)\s*\(")
_LOG_METHODS = frozenset({"log", "info", "warn", "warning", "error", "debug", "trace", "fatal", "critical", "exception", "verbose",
                          "silly", "http", "printf", "println", "print", "fprintf", "fprintln", "fprint", "d", "i", "w", "e", "v",
                          "write", "notice"})
_LOG_STOP = frozenset({"id", "name", "body", "message", "text", "content", "error", "err", "req", "res", "request", "response", "e", "msg"})
_LABEL_RE = re.compile(r"""([A-Za-z_][\w.-]*)\s*[=:](?!=)""")
_INTERP_RE = re.compile(r"""\$\{([^}]*)\}|\{([^{}]*)\}|%\((\w+)\)""")
_LITERAL_SPLIT_RE = re.compile(r"""([fFrRbBuU]{0,2}(?:'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`))""", re.S)


def logged_words(stmt: str) -> list[str]:
    """Names a log statement interpolates: code identifiers, `key=` labels and ${...}/{...} interpolations."""
    words: list[str] = []
    for chunk in _LITERAL_SPLIT_RE.split(stmt):
        if not chunk:
            continue
        if _LITERAL_SPLIT_RE.fullmatch(chunk):
            body = re.sub(r"^[fFrRbBuU]{0,2}.", "", chunk, count=1)[:-1]
            words.extend(lm.group(1).split(".")[-1].split("-")[-1] for lm in _LABEL_RE.finditer(body))
            for im in _INTERP_RE.finditer(body):
                words.extend([im.group(3)] if im.group(3) else _IDENT_RE.findall(im.group(1) or im.group(2) or ""))
        else:
            words.extend(_IDENT_RE.findall(chunk))
    return words


def x_logs(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    for m in _LOG_CALL_RE.finditer(code):
        callee = m.group("callee")
        if "." in callee and callee.rsplit(".", 1)[-1].lower() not in _LOG_METHODS:
            continue
        if re.search(r"(?:function|def|fn|func|void|static|class|async)\s+$", code[max(0, m.start() - 24):m.start()]):
            continue
        _args, close = call_args(code, m.end() - 1)
        if close < 0:
            continue
        stmt = code[m.end():close]
        fields: list[str] = ["request.body"] if re.search(_REQ + r"\.body\b(?!\s*\.)", stmt) else []
        cred = False
        for w in logged_words(stmt):
            if w.lower() in _LOG_STOP:
                continue
            res = classify(w)
            if not res or res[0] in LOG_SKIP_CLASSES:
                continue
            if _norm(w) not in {_norm(f) for f in fields}:
                fields.append(w)
            cred = cred or res[0] == "credential"
        if fields:
            rec = acc.logs.setdefault((src.rel, src.line(m.start())), {"fields": [], "cred": False})
            rec["fields"].extend(f for f in fields if f not in rec["fields"])
            rec["cred"] = rec["cred"] or cred


# Rights. Deletion is recorded only when an erase operation is found; a route or function that merely
# *looks* like account deletion is kept apart (scan.rights_name_only) because the deletion-fixture
# pattern is a handler that returns "deleted" and erases nothing.
_DELETE_NAME_RES = [
    re.compile(r"""(?:\.delete\(\s*|DELETE\s+)['"]?/?[\w./:{}-]*(?:account|users?/|/me\b|profile|gdpr|erase|my-?data)""", re.I),
    re.compile(r"""\b(?:def|function|async function|const)\s+(?:delete|remove|erase|close|deactivate|anonymi[sz]e)_?(?:my_?)?(?:account|user|profile|data|me)\b""", re.I),
    re.compile(r"""['"`]/?[\w./:{}-]*(?:delete-?account|account/delete|forget-?me|right-to-erasure|erase-?my)[\w./:{}-]*['"`]""", re.I),
]
_ERASE_SQL_RE = re.compile(r"""\bDELETE\s+FROM\s+[`"\[]?(\w+)[`"\]]?([^;`"']{0,160})""", re.I)
_ERASE_OWNER_RE = re.compile(r"\b(?:user|owner|account|customer|member|author)_?id\b", re.I)
_ERASE_ORM_RE = re.compile(
    r"\.(?:deleteOne|deleteMany|destroy|findByIdAndDelete|findOneAndDelete|findByIdAndRemove)\s*\(|\.remove\s*\(\s*\{|"
    r"\bsession\.delete\s*\(|\.delete\s*\(\s*\)|\bprisma\.\w+\.delete(?:Many)?\s*\(|\.del\s*\(\s*\)|"
    r"\bos\.(?:remove|unlink)\s*\(|\bshutil\.rmtree\s*\(|\bfs\.(?:rm|rmSync|unlink|unlinkSync)\s*\(")
_RIGHTS_OTHER: list[tuple[str, re.Pattern[str]]] = [
    ("access_export", re.compile(r"""\b(?:def|function|async function|const)\s+(?:export|download|dump|get)_?(?:my_?)?(?:user_?)?(?:data|account_?data|personal_?data)\b|\bsubject_?access\b|\bdsar\b""", re.I)),
    ("access_export", re.compile(r"""['"`]/?[\w./:{}-]*(?:data-?export|export-?data|export-?my|download-?my|my-?data|/gdpr|account/export|me/export|/dsar)[\w./:{}-]*['"`]""", re.I)),
    ("correction", re.compile(r"""\.(?:put|patch)\(\s*['"]/?[\w./:{}-]*(?:profile|account|users?/|/me\b)""", re.I)),
    ("correction", re.compile(r"""\b(?:def|function|async function|const)\s+(?:update|edit|change|correct)_?(?:my_?)?(?:profile|account|user|email|me)\b""", re.I)),
    ("opt_out_sale_share", re.compile(r"""do[-_ ]?not[-_ ]?(?:sell|share)|donotsell|opt[-_]?out[-_]?(?:of[-_]?)?(?:sale|sharing|sell)|\bSec-GPC\b|\bglobal[-_]?privacy[-_]?control\b""", re.I)),
]
_ERASE_WINDOW_LINES = 60
_NAME_ONLY_NOTE = "found by endpoint / function name only; the handler's behaviour is not verified"
_ERASE_NOTE = "erase operation found; whether it removes all of the user's personal data is not verified"


_RIGHTS_WORDS = ("export", "download", "dump", "dsar", "gdpr", "subject", "access", "update", "edit", "change", "correct",
                 "sell", "share", "gpc", "opt-out", "opt_out", "optout", "opt out", "privacy")
_DELETE_WORDS = ("delete", "erase", "remove", "close", "deactivate", "anonymi", "forget", "right-to-erasure")
_ERASE_WORDS = ("delete", "destroy", "remove", "unlink", "rmtree", "del(", "del (", "drop")


def x_rights(src: Source, acc: Acc, ctx: Ctx) -> None:
    code = src.code
    low = code.lower()                                  # cheap prefilters: most files mention none of these
    if any(w in low for w in _RIGHTS_WORDS):
        for key, rx in _RIGHTS_OTHER:
            for m in rx.finditer(code):
                acc.add_right(key, src.ref(m.start()), _NAME_ONLY_NOTE)
    name_lines: list[int] = []
    if any(w in low for w in _DELETE_WORDS):
        for rx in _DELETE_NAME_RES:
            for m in rx.finditer(code):
                name_lines.append(src.line(m.start()))
    erase_hits: list[tuple[int, str]] = []
    if any(w in low for w in _ERASE_WORDS):
        for m in _ERASE_SQL_RE.finditer(code):
            if user_like_table(m.group(1)) or _ERASE_OWNER_RE.search(m.group(2)):
                erase_hits.append((src.line(m.start()), "sql"))
        for m in _ERASE_ORM_RE.finditer(code):
            erase_hits.append((src.line(m.start()), "orm"))
    confirmed = False
    for line, kind in erase_hits:
        near_name = any(0 <= line - nl <= _ERASE_WINDOW_LINES for nl in name_lines)
        if kind == "sql" or near_name:
            acc.add_right("deletion", f"{src.rel}:{line}", _ERASE_NOTE)
            confirmed = True
    if name_lines and not confirmed:
        for nl in name_lines:
            acc.rights_name_only.setdefault("deletion", set()).add(f"{src.rel}:{nl}")


_RETENTION_RE = re.compile(
    r"\b(?:data_?retention|retention_?(?:days|period|policy)|purge_?old|delete_?old|cleanup_?old|prune_?old|expireAfterSeconds|expire_?after|ttl_?(?:seconds|days))\b|"
    r"\bDELETE\s+FROM\s+\w+\s+WHERE\s+[^;\n]*\b(?:created|updated|timestamp|date|expires?|age|older)\w*", re.I)


def x_retention(src: Source, acc: Acc, ctx: Ctx) -> None:
    for m in _RETENTION_RE.finditer(src.code):
        if len(acc.retention_refs) < 50:
            acc.retention_refs.append(src.ref(m.start()))


EXTRACTORS: dict[str, list[Callable[[Source, Acc, Ctx], None]]] = {
    "js": [x_sql, x_js_models, x_js_requests, x_js_analytics, x_js_storage, x_set_cookie_header, x_hosts, x_sdk_imports, x_stores, x_logs, x_rights, x_retention],
    "html": [x_html, x_js_requests, x_js_analytics, x_js_storage, x_hosts, x_sdk_imports, x_rights],
    "py": [x_sql, x_python, x_py_regex, x_set_cookie_header, x_hosts, x_sdk_imports, x_stores, x_logs, x_rights, x_retention],
    "sql": [x_sql],
    "prisma": [x_prisma, x_hosts],
    "generic": [x_sql, x_generic_models, x_hosts, x_stores, x_logs, x_rights, x_retention],
    "css": [x_hosts],
    "config": [x_hosts, x_stores],
}


# --------------------------------------------------------------------------- orchestration

def _new_meta() -> dict[str, Any]:
    return {"files_scanned": 0, "bytes_read": 0, "skipped_budget": 0, "skipped_large": 0, "skipped_binary": 0, "skipped_minified": 0,
            "skipped_test_dirs": 0, "skipped_test_files": 0, "truncated": False}


def _finalize_python_models(acc: Acc) -> None:
    for p in acc.pending_py:
        via = "api-body" if p["cls_name"] in acc.request_models and p["kind"] in ("pydantic", "dataclass") else "model"
        acc.add_field(p["name"], p["res"][0], via, p["ref"], kind=p["res"][1])


def _link_events_to_hosts(acc: Acc) -> None:
    for ev in acc.event_files.values():
        hosts = set(ev["hosts"]) | set(ev["sdk"]) | {acc.url_vars[w] for w in ev["words"] if w in acc.url_vars}
        hosts |= {h for h, rec in acc.third.items() if rec["vendor"] in ev["vendors"]}      # gtag() in app.js, <script> in index.html
        for h in hosts:
            rec = acc.third.get(h)
            if rec and rec["analytics_like"]:
                rec["data_sent"].update(ev["fields"])


def _norm(name: str) -> str:
    return re.sub(r"[_\-]", "", name).lower()


def _compute_usage(root: Path, files: list[tuple[str, str]], acc: Acc) -> dict[str, bool]:
    """used_in_code: does the bare name appear anywhere outside its own definition / INSERT lines?"""
    wanted: dict[str, set[str]] = {}
    for name, rec in acc.fields.items():
        if rec["usage"]:
            wanted.setdefault(_norm(rec["bare"]), set()).add(name)
    if not wanted:
        return {}
    hits: dict[str, set[str]] = {k: set() for k in wanted}
    ident = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
    usage_meta = _new_meta()
    for rel, kind in files:
        if kind in ("sql", "prisma", "config"):
            continue
        src = load_source(root, rel, kind, usage_meta)
        if src is None:
            continue
        for ln, line in enumerate(src.code.split("\n"), 1):
            if not line.strip() or re.search(r"(?i)\bINSERT\s+(?:OR\s+\w+\s+)?INTO\b", line):
                continue
            for w in ident.findall(line):
                k = _norm(w)
                if k in hits:
                    hits[k].add(f"{rel}:{ln}")
    return {name: bool(hits[key] - acc.fields[name]["def_lines"]) for key, names in wanted.items() for name in names}


def _prov(refs: Iterable[str], notes: Iterable[str] = ()) -> dict[str, Any]:
    refs = sorted_refs(refs)
    notes = set(notes)
    if len(refs) > MAX_REFS:
        notes.add(f"{len(refs) - MAX_REFS} further reference(s) omitted")
        refs = refs[:MAX_REFS]
    out: dict[str, Any] = {"source": "code", "refs": refs}
    if notes:
        out["note"] = "; ".join(sorted(notes))
    return out


def build_entries(acc: Acc, usage: dict[str, bool]) -> dict[str, Any]:
    retention_found = bool(acc.retention_refs)
    fields = []
    for name in sorted(acc.fields):
        rec = acc.fields[name]
        e: dict[str, Any] = {"name": name, "classification": rec["classification"]}
        if rec["classification"] == "sensitive" and rec["sensitive_kind"]:
            e["sensitive_kind"] = rec["sensitive_kind"]
        e["collected_via"] = [v for v in VIA_ORDER if v in rec["via"]]
        notes = set(rec["notes"])
        if name in usage:
            e["used_in_code"] = usage[name]
            if not usage[name]:
                notes.add("no other reference to this name found outside its definition/INSERT; it may still be read dynamically (SELECT *, serializers)")
        if not retention_found and rec["via"] & {"model", "api-body", "form"}:
            e["retention"] = "none defined"
        e["provenance"] = _prov(rec["refs"], notes)
        fields.append(e)

    third = []
    for host in sorted(acc.third):
        rec = acc.third[host]
        e = {"host": host}
        if rec["vendor"]:
            e["vendor"] = rec["vendor"]
        e["role"] = "unknown"
        if rec["data_sent"]:
            e["data_sent"] = sorted(rec["data_sent"])
        if rec["purpose"]:
            e["purpose"] = rec["purpose"]
        e["provenance"] = _prov(rec["refs"], rec["notes"])
        third.append(e)

    storage = []
    for (mech, name) in sorted(acc.storage):
        rec = acc.storage[(mech, name)]
        nec = rec["necessity"] or _client_storage_necessity(name)
        e = {"name": name, "mechanism": mech, "set_by": rec["set_by"], "necessity": nec}
        if rec["expiry"]:
            e["expiry"] = rec["expiry"]
        notes = set(rec["notes"])
        if nec != "unknown":
            notes.add("necessity inferred from the storage name only; confirm")
        e["provenance"] = _prov(rec["refs"], notes)
        storage.append(e)

    stores = [{"name": name, "kind": kind, "encrypted_at_rest": "unknown",
               "provenance": _prov(acc.stores[(kind, name)]["refs"], acc.stores[(kind, name)]["notes"])}
              for (kind, name) in sorted(acc.stores)]

    logs = []
    for (rel, line) in sorted(acc.logs):
        rec = acc.logs[(rel, line)]
        loc = f"{rel}:{line}"
        logs.append({"location": loc, "fields_logged": rec["fields"], "contains_credential": bool(rec["cred"]),
                     "provenance": {"source": "code", "refs": [loc]}})

    inv: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": rglib.now_iso(),
        "confirmed_by_user": False,
        "fields": fields,
        "third_parties": third,
        "client_storage": storage,
        "stores": stores,
        "log_sinks": logs,
    }
    if acc.rights:
        inv["rights"] = {k: _prov(acc.rights[k]["refs"], acc.rights[k]["notes"])
                         for k in ("access_export", "deletion", "correction", "opt_out_sale_share") if k in acc.rights}
    return inv


def _add_vendor_script_cookies(acc: Acc) -> None:
    """Cookies a known vendor script is documented to set, inferred from the script/SDK being present."""
    for rec in list(acc.third.values()):
        for cname, necessity in VENDOR_COOKIES.get(rec.get("vendor") or "", []):
            acc.add_storage("cookie", cname, sorted_refs(rec["refs"])[0], set_by="third-party", necessity=necessity,
                            note=f"set by {rec['vendor']} script; inferred from script inclusion, not observed at runtime")


def scan_project(project: str | Path, include_tests: bool = False) -> tuple[dict[str, Any], dict[str, Any]]:
    """Scan a project. Returns (inventory dict, meta dict). Writes nothing."""
    root = Path(project).resolve()
    meta = _new_meta()
    acc = Acc()
    ctx = Ctx()
    files = walk_project(root, include_tests, meta)
    scanned: list[tuple[str, str]] = []
    for rel, kind in files:
        src = load_source(root, rel, kind, meta)
        if src is None:
            continue
        meta["files_scanned"] += 1
        scanned.append((rel, kind))
        for fn in EXTRACTORS.get(kind, []):
            try:
                fn(src, acc, ctx)
            except Exception as exc:                       # a heuristic must never abort the scan
                acc.warnings.append(f"{fn.__name__} failed on {rel}: {type(exc).__name__}")
    _finalize_python_models(acc)
    _link_events_to_hosts(acc)
    _add_vendor_script_cookies(acc)
    inv = build_entries(acc, _compute_usage(root, scanned, acc))
    text = json.dumps(inv)
    if rglib.find_secrets(text):                           # defence in depth: no recognisable secret in the draft
        inv = json.loads(rglib.redact_text(text))
        acc.warnings.append("a secret-shaped string was redacted from the draft")
    if meta["truncated"]:
        acc.warnings.append(f"scan truncated (file or {MAX_TOTAL_BYTES // 1_000_000} MB budget reached): the draft is incomplete")
    meta.update({
        "warnings": sorted(set(acc.warnings)),
        "unclassified_columns": acc.unclassified[:200],
        "retention_like_code": sorted_refs(acc.retention_refs)[:20],
        "rights_name_only": {k: sorted_refs(v) for k, v in acc.rights_name_only.items()},
    })
    return inv, meta


def scan(project: str | Path, include_tests: bool = False) -> dict[str, Any]:
    """Convenience wrapper: just the inventory dict."""
    return scan_project(project, include_tests)[0]


# --------------------------------------------------------------------------- merge with an existing inventory

SECTION_KEYS: dict[str, Callable[[dict[str, Any]], Any]] = {
    "fields": lambda e: e["name"],
    "third_parties": lambda e: e["host"],
    "client_storage": lambda e: (e["mechanism"], e["name"]),
    "stores": lambda e: (e["kind"], e["name"]),
    "log_sinks": lambda e: e["location"],
}
# Judgement keys: an existing (non-default) value always wins, because the user may have corrected the scanner's guess.
PREFER_EXISTING = {
    "fields": ("purposes", "lawful_basis"),
    "third_parties": ("vendor", "role", "purpose", "transfer_region"),
    "client_storage": ("necessity",),
    "stores": ("region",),
    "log_sinks": (),
}
# Facts the code can change: the fresh scan wins, and an existing value only fills a gap or replaces a default.
FILL_ONLY = {
    "fields": ("retention", "encrypted_at_rest"),
    "third_parties": (),
    "client_storage": ("expiry", "set_by"),
    "stores": ("encrypted_at_rest",),
    "log_sinks": (),
}
# Keys only a human fills in: an entry that carries one of these is kept (flagged) even after its code disappears.
USER_ONLY = {
    "fields": ("purposes", "lawful_basis", "retention", "encrypted_at_rest"),
    "third_parties": ("role", "transfer_region"),
    "client_storage": (),
    "stores": ("encrypted_at_rest", "region"),
    "log_sinks": (),
}
HUMAN_KEYS = {sec: PREFER_EXISTING[sec] + FILL_ONLY[sec] + (("data_sent",) if sec == "third_parties" else ()) for sec in PREFER_EXISTING}
DEFAULT_VALUES = frozenset({"unknown", "none defined"})


def _is_annotation(value: Any) -> bool:
    """A value a human could have written (not empty, not a scanner default)."""
    return value not in (None, [], "") and not (isinstance(value, str) and value in DEFAULT_VALUES)


def _is_user(entry: Any) -> bool:
    return isinstance(entry, dict) and (entry.get("provenance") or entry).get("source") == "user"


def user_owned(inv: Any) -> bool:
    """True if the inventory holds anything a human wrote or confirmed (so a plain rescan must not clobber it)."""
    if not isinstance(inv, dict):
        return False
    if inv.get("confirmed_by_user"):
        return True
    if any(_is_user(e) for sec in SECTION_KEYS for e in inv.get(sec) or []):
        return True
    return any(_is_user(v) for v in (inv.get("rights") or {}).values())


def merge_inventory(fresh: dict[str, Any], existing: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Keep user-owned entries and human annotations; refresh code-derived data. Returns (merged, report)."""
    merged = dict(fresh)
    report = {"kept_user_entries": 0, "carried_annotations": 0, "kept_stale": 0, "dropped_stale": 0}
    code_set_changed = False
    for sec, keyfn in SECTION_KEYS.items():
        old = {keyfn(e): e for e in existing.get(sec) or [] if isinstance(e, dict)}
        new = {keyfn(e): e for e in fresh.get(sec, [])}
        out: dict[Any, dict[str, Any]] = {}
        for key, e in new.items():
            prior = old.get(key)
            if prior is None:
                code_set_changed = True
                out[key] = e
            elif _is_user(prior):
                out[key] = prior
                report["kept_user_entries"] += 1
            else:
                e = dict(e)
                for hk in HUMAN_KEYS[sec]:
                    pv, fv = prior.get(hk), e.get(hk)
                    if not _is_annotation(pv):
                        continue
                    if hk == "data_sent":
                        e[hk] = sorted(set(fv or []) | set(pv))
                    elif hk in PREFER_EXISTING[sec] or not _is_annotation(fv):
                        report["carried_annotations"] += fv != pv
                        e[hk] = pv
                out[key] = e
        for key, prior in old.items():
            if key in new:
                continue
            if _is_user(prior):
                out[key] = prior
                report["kept_user_entries"] += 1
            elif any(_is_annotation(prior.get(hk)) for hk in USER_ONLY[sec]):
                prior = json.loads(json.dumps(prior))
                prov = prior.setdefault("provenance", {"source": "code", "refs": []})
                prov["note"] = (prov["note"] + "; " if prov.get("note") else "") + \
                    "not found by the latest scan; refs may be stale (kept because it carries user annotations)"
                out[key] = prior
                report["kept_stale"] += 1
            else:
                report["dropped_stale"] += 1
                code_set_changed = True
        merged[sec] = [out[k] for k in sorted(out, key=str)]
    rights = dict(fresh.get("rights") or {})
    for k, v in (existing.get("rights") or {}).items():
        if _is_user(v):
            rights[k] = v
            report["kept_user_entries"] += 1
    if rights:
        merged["rights"] = rights
    else:
        merged.pop("rights", None)
    merged["confirmed_by_user"] = bool(existing.get("confirmed_by_user")) and not code_set_changed
    return merged, report


# --------------------------------------------------------------------------- CLI

def counts(inv: dict[str, Any]) -> dict[str, int]:
    c = {k: len(inv.get(k, [])) for k in ("fields", "third_parties", "client_storage", "stores", "log_sinks")}
    c["rights"] = len(inv.get("rights") or {})
    return c


def format_summary(out: Path, inv: dict[str, Any], meta: dict[str, Any], merge: dict[str, Any] | None) -> str:
    skipped = [f"{meta[k]} {label}" for k, label in (("skipped_large", "large"), ("skipped_binary", "binary"), ("skipped_minified", "minified")) if meta[k]]
    lines = [f"data inventory draft written: {out}",
             "  " + ", ".join(f"{k}={v}" for k, v in counts(inv).items()),
             f"  scanned {meta['files_scanned']} files" + (f" (skipped: {', '.join(skipped)})" if skipped else "")
             + (", TRUNCATED at the file limit" if meta["truncated"] else ""),
             f"  confirmed_by_user: {str(inv['confirmed_by_user']).lower()}  "
             "(a human must review: purposes, lawful basis, roles and retention are not inferred)"]
    if merge:
        lines.append("  merge: " + ", ".join(f"{k}={v}" for k, v in merge.items()))
    if meta["retention_like_code"]:
        lines.append("  retention-like code found (not mapped to fields): " + ", ".join(meta["retention_like_code"][:5]))
    for right, refs in meta["rights_name_only"].items():
        lines.append(f"  {right}: handler found by name only, no erase operation: {', '.join(refs[:5])} (not recorded under rights)")
    lines.append(f"  unclassified model columns: {len(meta['unclassified_columns'])} (listed with --json)")
    lines.extend(f"  warning: {w}" for w in meta["warnings"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Scan a project's code and write a draft data-inventory.yaml (read-only on the project).")
    ap.add_argument("project", nargs="?")
    ap.add_argument("--project", dest="project_opt", help=argparse.SUPPRESS)       # compatibility alias
    ap.add_argument("--out", help="output path (default: <project>/.release-gate/data-inventory.yaml)")
    ap.add_argument("--json", action="store_true", help="print a JSON result (counts, warnings, the inventory) instead of a text summary")
    ap.add_argument("--merge-existing", action="store_true",
                    help="keep user-sourced entries and user annotations from an existing inventory at the output path")
    ap.add_argument("--include-tests", action="store_true", help="also scan test directories and test files (skipped by default)")
    ap.add_argument("--validate", action="store_true", help=argparse.SUPPRESS)      # always on; accepted for compatibility
    args = ap.parse_args(argv)

    project = args.project or args.project_opt
    if not project or not Path(project).is_dir():
        print(f"not a directory: {project}", file=sys.stderr)
        return 2
    out = Path(args.out) if args.out else rglib.state_dir(project) / "data-inventory.yaml"

    existing: Any = None
    if out.exists():
        try:
            existing = rglib.load_data(out)
        except Exception as exc:                           # unreadable YAML: never clobber it
            print(f"existing inventory at {out} cannot be parsed ({type(exc).__name__}); refusing to overwrite it. "
                  "Fix or remove it, or pass a different --out.", file=sys.stderr)
            return 3
        if not args.merge_existing and user_owned(existing):
            print(f"{out} contains user-confirmed or user-sourced entries; refusing to overwrite them.\n"
                  "Re-run with --merge-existing to keep them, or pass a different --out.", file=sys.stderr)
            return 3

    inv, meta = scan_project(project, include_tests=args.include_tests)
    merge_report = None
    if args.merge_existing and isinstance(existing, dict):
        inv, merge_report = merge_inventory(inv, existing)

    errors = rglib.validate(inv, "data-inventory")
    if errors:
        print("internal error: generated inventory does not match the schema:", file=sys.stderr)
        for e in errors[:20]:
            print(f"  {e}", file=sys.stderr)
        return 1
    rglib.dump_data(out, inv)

    if args.json:
        print(json.dumps({"out": str(out), "counts": counts(inv), "merge": merge_report, "scan": meta, "inventory": inv},
                         indent=2, default=str))
    else:
        print(format_summary(out, inv, meta, merge_report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
