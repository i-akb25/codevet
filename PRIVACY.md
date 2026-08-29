# Privacy Policy

CodeVet is a local command-line tool. There is no CodeVet server, no account,
and no telemetry — this document describes exactly what data the tool
touches and where it goes, based on what the code actually does.

## What CodeVet does NOT do

- It does not collect, transmit, or store analytics about you or your usage
- It does not send your source code, file contents, or scan results to any
  CodeVet-operated server — there isn't one
- It does not require a sign-up, account, or API key to use

## What actually happens when you run a scan

**Secret scanning (`gitleaks`)** — runs entirely on your machine, reading
files from the path you point it at. Nothing leaves your machine during
this step.

**Dependency scanning (`npm audit`)** — this step sends your project's
package names and version numbers to the public npm registry
(`registry.npmjs.org`) so it can be checked against npm's own published
vulnerability advisory database. This is standard `npm audit` behavior,
identical to running it yourself directly — CodeVet does not add any
additional data to that request, and the registry is operated by npm/GitHub,
not by CodeVet.

**Scanning a git/GitHub URL** — CodeVet runs a normal `git clone` against
the URL you provide. This follows whatever access rules that repository
host already has (e.g. a private GitHub repo still requires your existing
git credentials — CodeVet doesn't bypass or store these).

**Installing CodeVet itself** — the `postinstall` step downloads the
`gitleaks` binary directly from its official GitHub releases page, matched
to your OS/architecture. No user data is included in that request.

## Local files CodeVet creates

- `.codevet/config.json` — stores which scanners you've enabled/disabled
  for a project. Stays on your machine, auto-added to `.gitignore`, never
  transmitted anywhere.
- Temporary clone folders (for URL scans) — created under your OS's temp
  directory, deleted automatically unless you choose to keep the result.

## Third-party services this tool talks to

| Service | What for | Whose policy applies |
|---|---|---|
| npm registry (`registry.npmjs.org`) | Dependency vulnerability lookups | [npm's privacy policy](https://docs.npmjs.com/policies/privacy) |
| GitHub (`github.com`, releases) | Downloading the gitleaks binary; cloning repos you point CodeVet at | [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement) |

## Compliance posture (India's DPDP Act, and equivalents elsewhere)

CodeVet does not collect, store, or process personal data as defined under
India's Digital Personal Data Protection Act, 2023 (or GDPR, CCPA, etc.) —
there is no CodeVet-operated backend for any personal data to flow into.
Scanning happens entirely on your machine; the only external calls are the
ones described above (npm registry, GitHub), each governed by that
service's own policy, not CodeVet's.

If CodeVet ever introduces a feature that does process personal data (for
example, an account-based hosted dashboard), that feature will document
its own lawful basis, retention period, and user rights under applicable
law before it ships — not retroactively.

## Changes to this policy

If CodeVet ever adds a feature that changes this (for example, an optional
hosted dashboard mentioned as a possible future addition), that feature
will be opt-in and this document will be updated to describe it plainly
before it ships.
