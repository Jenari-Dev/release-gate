# Disclaimer

Please read this before using release-gate. By installing or running it you agree to these terms. They add to, and do not replace, the warranty and liability terms in the [MIT License](LICENSE).

## No warranty, no guarantee

release-gate is provided "as is", without warranty of any kind. A report from release-gate, including a `SHIP` verdict, is **not** a guarantee that your software is free of vulnerabilities, bugs, privacy problems, or legal risk. Automated scanners and AI-assisted review miss things. The report says what was checked and how; anything it did not check, it marks `NOT-TESTED`.

## Not professional advice

- **Not legal advice.** Generated privacy policies, terms, cookie policies, EULAs and other documents are drafts based on what the tool found in your code. They may be incomplete or wrong for your situation. Laws change, and the bundled law reference data has dates for a reason. Have a qualified lawyer review anything before you publish it or rely on it.
- **Not a penetration test or security certification.** release-gate does not replace a professional security assessment, audit, or certification.
- **Not compliance certification.** It does not certify compliance with GDPR, CCPA, COPPA, APPI or any other law, standard or platform policy.

## You are responsible for

- **Authorization.** Only test systems you own or have written permission to test. release-gate refuses targets outside the scope you confirm, but you are responsible for what you confirm. Unauthorized testing may be illegal.
- **Your environment.** release-gate installs and runs third-party tools (scanners, browsers, load generators) and starts your application locally. Run it where that is acceptable, ideally a development machine or a disposable environment, never with production credentials loaded.
- **Your data.** Dynamic tests create test accounts and send test traffic. Back up anything you care about first. Never point it at real user data.
- **What you ship.** The decision to release, and everything that follows from it, is yours.

## Limitation of liability

To the fullest extent permitted by law, the authors and contributors are not liable for any damages, losses, claims, fines or costs arising from the use of, or inability to use, release-gate or its output. This includes missed vulnerabilities, data loss, service disruption, regulatory action, or reliance on generated documents. If your jurisdiction does not allow some of these exclusions, they apply to the maximum extent it does allow.

## Third-party tools

release-gate calls third-party tools (for example gitleaks, trufflehog, semgrep, osv-scanner, trivy, syft, OWASP ZAP, nuclei, k6, Playwright). Each has its own license and its own authors. release-gate is not affiliated with or endorsed by any of them. Their results are reported as they produced them, with release-gate's verification notes.

## Trademarks

Names of products, companies, laws and platforms are used only to identify them. No affiliation or endorsement is implied.
