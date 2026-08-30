# CodeVet

**Vet your code before it ships.** A free, open-source security co-pilot for
developers who aren't security experts — students, solo/indie developers,
and small teams who can't justify an enterprise AppSec platform yet.

CodeVet doesn't invent its own detection logic. It orchestrates trusted,
independently-maintained tools (`gitleaks`, `npm audit`, `pip-audit`,
`bearer`) and translates their output into plain language: what's wrong,
how severe it is, why it matters, and — where possible — the exact working
fix code, not just a description.

```
$ npx codevet scan

CodeVet — scanning .

Detected: node (package.json)

Checking for exposed secrets...
✖ 1 exposed secret(s) found: .env:12 — not gitignored

Checking dependencies for known vulnerabilities...
✖ axios — HIGH — MITM via proxy config prototype pollution — fix: axios@1.19.0

Checking for missing security middleware...
 CRITICAL  Table 'payments' may be missing Row Level Security
✖ HIGH No rate limiting found
○ MODERATE No security headers configured
  Suggested fix — security/helmet.config.js: [real, ready-to-paste code]

Checking personal data flow (via bearer)...
✔ No personal-data-flow risks found.
```

## Install

```bash
npm install -g @i.akb-viora/codevet          # global — run `codevet` from any project
# or
npm install --save-dev @i.akb-viora/codevet  # per-project — run via `npx codevet`
```

## Use

```bash
codevet scan                              # scan the current directory
codevet scan ./some/folder                # scan a specific local folder
codevet scan https://github.com/user/repo # review a repo before you trust it
codevet fix                               # safely upgrade flagged dependencies
codevet fix --force                       # allow major-version upgrades
codevet remove-dependency <name>          # explicitly uninstall a flagged package
codevet clean ./some-repo-you-kept        # remove a repo CodeVet cloned earlier
codevet config status                     # see which checks are enabled
codevet config disable <check>            # turn a check off for this project
```

Full command reference: [`docs/HELP.md`](./docs/HELP.md).

## What it checks today

| Check | Tool | Severity model |
|---|---|---|
| Leaked secrets — API keys, credentials, connection strings, Supabase service-role-key exposure | `gitleaks` (extended ruleset) | Every finding is real and confirmed |
| Dependency vulnerabilities (Node) | `npm audit` | CRITICAL/HIGH/MODERATE/LOW from the advisory database. Skipped (not failed) on pnpm-managed projects — a confirmed bug in npm itself, run `pnpm audit` directly for those |
| Dependency vulnerabilities (Python) | `pip-audit` | Unranked — PyPA's database has no severity field; prioritize by whether a fix exists |
| Missing security middleware — no helmet, no rate limiting, wide-open CORS, error responses leaking internals, missing Supabase Row Level Security | CodeVet's own heuristic scanner | CRITICAL/HIGH/MODERATE, each with a `Verify:` note on how the check could be wrong |
| Personal data flow — logging or transmitting PII, secrets, etc. | `bearer` | CRITICAL/HIGH/MODERATE/LOW. **No native Windows build** — unavailable there, everything else still works |

**CRITICAL** means fix it before anyone else touches the code. **HIGH**
means fix before launch. **MODERATE** is real but rarely the sole cause of
an incident. See [`docs/SECURITY-CHECKLIST.md`](./docs/SECURITY-CHECKLIST.md)
for the full severity-annotated checklist this is built around.

## Reviewing an unfamiliar repo before you trust it

```bash
codevet scan https://github.com/someone/some-repo
```

Clones to a temp folder, scans it, and asks before keeping anything if
issues are found. Decline and nothing is left on disk. Accept and it's
moved next to where you ran the command, with a provenance marker so
`codevet clean` can safely identify and remove it later.

## Running automatically on every PR

```yaml
# .github/workflows/codevet.yml
name: CodeVet
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codevet/codevet@v1
```

Posts results as a PR comment. Fails the check on critical/high findings
by default — see [`docs/HELP.md`](./docs/HELP.md) to make it advisory-only.

## Works inside your AI coding CLI

CodeVet ships as an Agent Skill — ask Claude Code, Cursor, or OpenCode to
"scan this project with CodeVet" and it runs directly in conversation. See
[`AGENTS.md`](./AGENTS.md).

## What it doesn't do (see [`TERMS.md`](./TERMS.md) for the full scope)

Not a malware/antivirus scanner. Not a replacement for a professional
security audit on anything handling real user data or payments at scale.
A clean scan means the checks CodeVet currently runs found nothing — not a
certification.

## Why this exists

Every existing free security tool — Semgrep, Trivy, GitGuardian — is built
for teams that already have security expertise. Nobody was serving the
developer who's never heard of a CVE and just wants to know if it's safe
to ship. That gap is what CodeVet is for. More in
[`docs/ABOUT.md`](./docs/ABOUT.md).

## Repository structure

See [`INFO.md`](./INFO.md) for a complete, file-by-file breakdown of this
repo — what everything is, who needs to touch it, and how to use it.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) — this project deliberately
avoids "vibe coding": every change is type-checked, tested against a real
reproduced scenario, and dependency-audited before merge.

## Security

Found a vulnerability in CodeVet itself? See [`SECURITY.md`](./SECURITY.md)
for private disclosure — please don't open a public issue for it.

## Privacy

CodeVet runs entirely locally — no account, no telemetry, no CodeVet
server. See [`PRIVACY.md`](./PRIVACY.md) for exactly what data each check
touches and where it goes (mainly: `npm audit` talks to the npm registry,
same as running it yourself).

## Author

**Anurag Kumar Bharti**  
Software Engineer

- **Portfolio:** [https://ace-akb.vercel.app](https://ace-akb.vercel.app)
- **GitHub:** [https://github.com/i-akb25](https://github.com/i-akb25)
- **LinkedIn:** [https://linkedin.com/in/anuragkumarbharti](https://linkedin.com/in/anuragkumarbharti)
- **Email:** anuragbhartiee25@gmail.com

## License

MIT — see [`LICENSE`](./LICENSE).
