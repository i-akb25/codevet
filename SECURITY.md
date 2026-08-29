# Security Policy

CodeVet is a security tool, so vulnerabilities in its own code are treated
seriously and reviewed quickly.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
Instead, use GitHub's private vulnerability reporting (Security tab →
"Report a vulnerability") on this repository, or email the maintainers
directly (see `README.md` for current contact details).

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce it
- Which version of CodeVet you tested against

## What happens next

- We'll acknowledge your report as soon as possible
- We'll investigate and let you know if it's confirmed, and roughly how
  long a fix will take
- We'll credit you in the fix's changelog, unless you'd prefer to stay
  anonymous
- Please give us a reasonable window to ship a fix before any public
  disclosure

## Scope

This policy covers CodeVet's own code (the CLI, the GitHub Action, the
postinstall script, the bundled `.gitleaks.toml` rules). It does not cover
vulnerabilities in the third-party tools CodeVet wraps (`gitleaks`,
`npm`/`npm audit`) — please report those directly to their respective
maintainers.

## A note on irony

Yes, a security scanner having its own vulnerabilities is exactly the kind
of thing it's supposed to help catch elsewhere. `npm audit` runs against
this project's own dependencies as part of CI for that reason — see
`CONTRIBUTING.md` for how that's enforced before any change is merged.
