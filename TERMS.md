# Terms of Use

By downloading, installing, or using CodeVet, you agree to the following.

## What CodeVet is

CodeVet is a free, open-source command-line tool that runs trusted
third-party security scanners (currently `gitleaks` for leaked secrets and
`npm audit` for known dependency vulnerabilities) against code you point it
at, and presents the results in plain language.

## No warranty, "as is"

CodeVet is provided **as is**, without warranty of any kind, under the MIT
License (see `LICENSE`). In plain terms:

- **CodeVet does not guarantee the absence of security vulnerabilities.**
  It surfaces *known, disclosed* issues via established scanners — it
  cannot detect novel vulnerabilities, zero-days, or issues outside the
  categories it currently checks (leaked secrets, known-vulnerable
  dependencies).
- **A clean scan result is not a certification.** It means the specific
  checks CodeVet currently runs found nothing — it is not a statement that
  the code is secure overall.
- **CodeVet is not a substitute for a professional security audit.**
  Anything handling real user data, payments, or production traffic at
  meaningful scale should still get a human security review before launch,
  regardless of what CodeVet reports.

## Your responsibility when scanning a repository

The pre-clone review feature (`codevet scan <url>`) shows you findings and
asks whether to keep a cloned repository. **CodeVet does not scan for
malware, viruses, or intentionally obfuscated malicious code beyond what
its underlying scanners cover** (currently: leaked secrets and known CVEs
in dependencies). Choosing to keep a repository despite a warning, or
running code from any repository at all, is done at your own judgment and
risk.

## Acceptable use

CodeVet is free to use, modify, and redistribute under the MIT License.
Don't use it, or represent it, in a way that implies a guarantee or
certification CodeVet does not actually provide (see "No warranty" above).

## Changes

These terms may be updated as CodeVet's feature set changes. Material
changes will be reflected here directly, in plain language, not buried in
a changelog.

## Related documents

- [`PRIVACY.md`](./PRIVACY.md) — what data the tool touches and where it goes
- [`SECURITY.md`](./SECURITY.md) — how to report a vulnerability in CodeVet itself
- [`LICENSE`](./LICENSE) — the MIT License text
