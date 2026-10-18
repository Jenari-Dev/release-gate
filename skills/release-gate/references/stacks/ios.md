# Stack: iOS (and macOS Apple-platform apps)

## Detect
`*.xcodeproj` / `*.xcworkspace` (reported as framework `ios`), `Info.plist`, `*.entitlements`, `Podfile` / `Podfile.lock`, `Package.swift` / `Package.resolved`, `Cartfile.resolved`, `PrivacyInfo.xcprivacy`. Swift/Obj-C sources. `Pods/` is skipped by the scanner.

## Pinned tools that apply
- semgrep: `swift/lang`, `swift/webview`, `swift/sqllite`, `c/lang` (Obj-C is partly covered); say SAST coverage is partial.
- osv-scanner on `Podfile.lock` and `Package.resolved`; gitleaks (provisioning profiles, `.p12`, `GoogleService-Info.plist`, API keys in plists and xcconfig); syft.
- Existing `.ipa` the user has built: unzip into a throwaway directory and `gitleaks dir` it (SEC-SECRETS-ARTIFACTS). Don't invoke `xcodebuild` without approval: build phases run project scripts.
- Not pinned: MobSF, `codesign`/`plutil` checks, SwiftLint. `NOT-TESTED: tool unavailable: <name>` (this host cannot build iOS apps anyway; say that for any dynamic claim).

## Gotchas to read for
- App Transport Security: `NSAllowsArbitraryLoads = true`, `NSExceptionDomains` with `NSExceptionAllowsInsecureHTTPLoads`, `NSAllowsArbitraryLoadsInWebContent`.
- Secrets in `UserDefaults`, plist files, Core Data/SQLite or the pasteboard instead of the Keychain; Keychain items with `kSecAttrAccessibleAlways*`; no data-protection class on sensitive files.
- URL schemes and Universal Links: handlers in `application(_:open:options:)` / `onOpenURL` that act on parameters without validation or confirmation; custom schemes used for OAuth redirects (interceptable; prefer Universal Links / ASWebAuthenticationSession).
- `WKWebView`: `javaScriptEnabled` with `WKScriptMessageHandler` bridges that run privileged actions for any loaded page, `allowFileAccessFromFileURLs`, loading arbitrary URLs; legacy `UIWebView`.
- Certificate validation disabled in `URLSessionDelegate` (`.useCredential` for any server trust), missing pinning where the app claims it, `NSLog`/`print` of tokens or PII in release builds.
- Entitlements: broad keychain access groups, App Groups sharing data across apps, `get-task-allow` true in a distribution build, unnecessary capabilities.
- Privacy: missing `PrivacyInfo.xcprivacy` required-reason APIs, tracking domains, SDK collection vs. the App Store privacy label, purpose strings (`NS*UsageDescription`) that don't match real use (PLAT-DISCLOSURES, PRIV-MINIMIZATION).
- Jailbreak/anti-tamper claims: client-side detection only raises effort; entitlements and purchases need server-side validation (receipt validation on the server).

## Check ids
SEC-SAST (partial), SEC-SECRETS-ARTIFACTS, SEC-SCA, PRIV-MINIMIZATION, PLAT-DISCLOSURES.
