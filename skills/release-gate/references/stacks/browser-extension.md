# Stack: Browser extension (Chrome, Edge, Firefox; MV2 / MV3)

## Detect
`manifest.json` with `manifest_version` 2 or 3 and a `background` or `content_scripts` key (reported as framework `browser-extension`). Also `service_worker`, `web_accessible_resources`, `externally_connectable`, `options_ui`, `*.crx`/`*.xpi` packages. Bundlers mean you also read `node.md`.

## Pinned tools that apply
- semgrep: `javascript/lang/security`, `typescript/lang/security`, `javascript/browser` rules if present (`ls` first).
- osv-scanner on the lockfile (bundled libraries count: vendored copies in `lib/` / `vendor/` are invisible to it, so grep for jQuery/lodash/etc. versions and say it was manual); gitleaks; syft.
- gitleaks on an existing built extension directory or unpacked package (SEC-SECRETS-ARTIFACTS): extension code is public the moment it is published, so any key in it is exposed.
- playwright is pinned; loading an unpacked extension for dynamic tests needs the user's go-ahead and a throwaway browser profile.
- Not pinned: web-ext lint, `crxcavator`-style analysers. `NOT-TESTED: tool unavailable: <name>`.

## Gotchas to read for
- Permissions: `<all_urls>` / `*://*/*` in `host_permissions` or `content_scripts.matches`, or broad `permissions` (`tabs`, `history`, `cookies`, `webRequest`, `webRequestBlocking`, `debugger`, `nativeMessaging`, `management`, `declarativeNetRequest` with broad rules). List each and ask what feature needs it; unused or over-broad ones are findings (and a store-review risk). `optional_permissions` requested at use time is the safer shape.
- Content Security Policy: `content_security_policy` with `'unsafe-eval'`, `'unsafe-inline'` or remote script origins (MV2); remote code loading is disallowed in MV3. Extension pages allowing `object-src` beyond `'self'`.
- Content scripts reading page data and sending it to the background or a server; `window.postMessage` / `chrome.runtime.onMessage` handlers that don't check `sender.id`, `sender.url` or `event.origin` and act on the payload.
- `externally_connectable` with wide `matches` or `ids`; `web_accessible_resources` exposing pages or scripts to every site (clickjacking, fingerprinting, loading your privileged page in an attacker frame).
- DOM sinks fed by page or API data: `innerHTML`, `insertAdjacentHTML`, `eval`, `new Function`, `setTimeout(string)`, `chrome.tabs.executeScript({code})`, `chrome.scripting.executeScript` with attacker-influenced `func` args.
- Storage and secrets: tokens in `chrome.storage.sync` (synced to the user's account) or `localStorage` of a content script (page-readable), API keys bundled in the package, `fetch` to HTTP endpoints, an update URL that is not the store.
- Data collection: browsing history, page content, form fields, identifiers sent to your server or third-party SDKs must appear in the data inventory, privacy policy and the store's data-use disclosures (PRIV-MINIMIZATION, PLAT-DISCLOSURES). Remote config that changes behaviour after review is a store-policy risk.

## Check ids
SEC-SAST, SEC-SCA, SEC-SECRETS-ARTIFACTS, PRIV-MINIMIZATION, PLAT-DISCLOSURES, LEGAL-POLICY-CONSISTENCY.
