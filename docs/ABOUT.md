# About CodeVet

## What it is

CodeVet is a free, open-source security co-pilot for developers who aren't
security experts — students, solo/indie developers, and small teams who
can't justify (or don't yet need) an enterprise AppSec platform.

Instead of building yet another scanning engine, CodeVet orchestrates
trusted, independently-maintained tools (`gitleaks`, `npm audit`, with more
planned) and translates their output into plain language: what's wrong, why
it matters in practice, and — where possible — the exact fix.

## Why it exists

Every existing free security tool is built for teams that already have
security expertise. Nobody was serving the developer who's never heard of
a CVE, doesn't know what CVSS means, and just wants to know if it's safe to
ship. That gap is what CodeVet is for.

## What it currently does

- Scans for leaked secrets and credentials (via `gitleaks`, with an
  extended ruleset for cases the defaults miss, like connection-string
  credentials)
- Scans dependencies for known, disclosed vulnerabilities (via `npm audit`)
- Lets you review a repository's risk *before* deciding to keep a local
  clone of it
- Runs entirely locally — no account, no server, no telemetry (see
  `PRIVACY.md`)

## What it doesn't do (yet, or by design)

- It is not a malware/antivirus scanner
- It does not detect novel or zero-day vulnerabilities — only known,
  disclosed issues in its scanners' databases
- It is not a replacement for a professional security audit on anything
  handling real user data or payments at meaningful scale

See `TERMS.md` for the full, precise scope of what a scan result does and
doesn't mean.

## Project values

- **No fake security** — findings are real, sourced from trusted scanners,
  never simulated or implied
- **No vibe coding** — every module has a defined responsibility, is
  type-checked in strict mode, and is tested against real, reproduced
  scenarios before being considered done
- **Minimum dependencies** — every third-party package is chosen
  deliberately (and audited — see `SECURITY.md`)

## License

MIT — see `LICENSE`.
