# Stack: Node.js / TypeScript

## Detect
`package.json`; lockfiles `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`. Frameworks reported include express, fastify, koa, next, react, vue, svelte, electron, tauri. A `package.json` with dependencies and no lockfile is a `lockfiles_missing` entry.

## Pinned tools that apply
- semgrep: `javascript/lang/security`, `typescript/lang/security`, plus `javascript/express`, `javascript/react`, `typescript/react`, `typescript/nestjs`, `typescript/angular` when present.
- osv-scanner on the lockfile; `npm audit --package-lock-only --json` is npm's own command (not pinned): use it as phase 2 says, record the npm version, and say `NOT-TESTED: tool unavailable: npm` when npm is absent. yarn/pnpm auditors are the same case.
- gitleaks; syft; gitleaks on built bundles (SEC-SECRETS-ARTIFACTS) when `dist/` or `.next/` already exists. Don't run the build without the user's approval (build scripts run project code).
- hadolint/trivy config for Dockerfiles; playwright for cookie audits on web UIs.

## Gotchas to read for
- `child_process.exec` with interpolated input, `eval`, `new Function`, `vm.runInThisContext`, `require(userInput)`.
- Prototype pollution: `Object.assign` / deep-merge helpers fed request bodies; `__proto__` keys.
- Express: no `helmet`, `cors({ origin: true, credentials: true })`, `trust proxy` mis-set, body parsers without limits, `express.static` over a directory holding secrets, error handler that returns stacks.
- NoSQL injection: query objects built from `req.body` (Mongo `$ne`, `$where`); regex built from user input (ReDoS).
- JWT: `alg: none` accepted, `jwt.decode` used instead of `verify`, secret in the repo.
- Server-only secrets exposed to the client through public-prefixed env vars (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`); source maps shipped to production.
- `dangerouslySetInnerHTML`, `innerHTML`, `v-html`, unsanitised markdown renderers.
- Install scripts (`preinstall`/`postinstall`) in the project or its dependencies; wildcard or `latest` version ranges; typosquat-looking names.

## Check ids
SEC-SAST, SEC-SCA, SEC-SECRETS-ARTIFACTS, SUP-PINNING, SEC-XSS-DYNAMIC, SEC-HEADERS-CORS, SEC-CSRF for web UIs.
