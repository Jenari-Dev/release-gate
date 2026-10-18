# Stack: Electron

## Detect
`electron` in `package.json` dependencies (reported as framework `electron`), `main.js` / `main.ts`, `preload.js`, `electron-builder.yml`, `forge.config.*`, `asar` archives. Also read `node.md`.

## Pinned tools that apply
- semgrep: `javascript/lang/security`, `typescript/lang/security`, plus any `electron` rule directory present in the snapshot (check `ls $SHARE/semgrep-rules/*/electron*`).
- osv-scanner on the lockfile (the Electron/Chromium version itself is a dependency: check it is a supported release); gitleaks; syft.
- gitleaks on existing packaged output (`app.asar` unpacked into a throwaway directory) for SEC-SECRETS-ARTIFACTS. Don't run the packager without approval.
- playwright is pinned, but driving the Electron app with it is out of scope here: dynamic Electron tests need the user's go-ahead and a local instance with synthetic data.
- Not pinned: Electronegativity, `@electron/fuses` checkers. `NOT-TESTED: tool unavailable: <name>`.

## Gotchas to read for (BrowserWindow / webPreferences)
- `nodeIntegration: true` in any window that loads remote or user-influenced content: XSS becomes remote code execution. Also `nodeIntegrationInWorker`, `nodeIntegrationInSubFrames`.
- `contextIsolation: false` (default is true since Electron 12; look for explicit false), `sandbox: false`, `webSecurity: false`, `allowRunningInsecureContent: true`, `experimentalFeatures`, `enableRemoteModule` / `@electron/remote`.
- Preload scripts exposing generic bridges through `contextBridge` (`ipcRenderer.send`/`invoke` passthrough, `fs`, `shell`, `child_process` handles) instead of narrow, named functions.
- `ipcMain.handle/on` handlers that don't check `event.senderFrame` / origin and don't validate arguments (path traversal, command injection, arbitrary URL open).
- `shell.openExternal(url)` with unvalidated URLs (`file:`, `smb:`, custom protocol handlers); `webContents.setWindowOpenHandler` / `will-navigate` missing, so a page can navigate the privileged window to anywhere.
- Loading remote content (`loadURL('https://...')`) in a privileged window; no Content-Security-Policy meta/header; `<webview>` enabled; custom protocol handlers (`protocol.registerFileProtocol`) that read arbitrary paths.
- Updater: `autoUpdater` feed over HTTP, unsigned builds, no code-signing / notarisation, update server credentials in the app. Secrets or API keys packed into the asar (it is not encryption).
- Fuses left at defaults (`RunAsNode`, `EnableNodeCliInspectArguments`, `OnlyLoadAppFromAsar`); `--inspect`/remote-debugging ports left on in shipping builds.

## Check ids
SEC-SAST, SEC-SCA, SEC-SECRETS-ARTIFACTS, SEC-XSS-DYNAMIC (if a web UI is served), PLAT-DISCLOSURES (signing).
