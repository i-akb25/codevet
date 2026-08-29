# INFO.md — What every file and folder in this repo is for

This is the complete map of the repository: what each piece does, who
actually needs to touch it, and how to use it. If you're new to this repo,
read this before poking around.

---

## The short version — what you actually need, by role

**Just want to use CodeVet?** You need none of this repo directly —
`npm install -g codevet`. Read [`README.md`](./README.md) and
[`docs/HELP.md`](./docs/HELP.md).

**Want to contribute code?** You need `src/`, `tests/`, and
[`CONTRIBUTING.md`](./CONTRIBUTING.md). Everything under `dist/` and
`templates/` is *generated* — never hand-edit it.

**Want to understand a specific check's logic?** Go straight to
`src/scanners/<name>.ts` — each one is self-contained and documented.

**Want to package/deploy CodeVet somewhere new?** You need `package.json`,
`scripts/postinstall.mjs`, and `action.yml`.

---

## Root-level files

| File | What it is | Who touches it |
|---|---|---|
| `README.md` | The landing page — install, usage, what it checks | Anyone updating the public-facing pitch |
| `INFO.md` | This file — the full repo map | Anyone adding/removing/renaming a file (keep this in sync) |
| `AGENTS.md` | Canonical instructions for using CodeVet from inside an AI coding CLI (Claude Code, Cursor, etc.) — the single source of truth all `.claude/`, `.cursor/`, `.opencode/` skill files point back to | Anyone changing how the CLI should be used conversationally |
| `CLAUDE.md` | One-line pointer to `AGENTS.md`, so Claude Code picks up the instructions automatically | Rarely — only if the pointer pattern itself changes |
| `LICENSE` | MIT license text | Legal only |
| `PRIVACY.md` | Exactly what data each check touches and where it goes (no telemetry, no CodeVet server) | Update if a new scanner talks to a new external service |
| `TERMS.md` | What a scan result does and doesn't mean — no-warranty language | Update if the product's scope/guarantees change |
| `SECURITY.md` | How to report a vulnerability *in CodeVet itself* (private disclosure) | Rarely |
| `CODE_OF_CONDUCT.md` | Standard OSS contributor conduct policy | Rarely |
| `CONTRIBUTING.md` | Engineering standards, code-quality bans, Definition of Done, AI-assisted-contribution guidance | Update when the engineering bar or contribution process changes |
| `action.yml` | The composite GitHub Action definition — what `uses: codevet/codevet@v1` actually runs in someone else's CI | Update when the scan command's flags or the PR-comment flow changes |
| `package.json` | Dependencies, `bin` entry (makes `codevet` a real command), build/test/publish scripts | Anyone adding a dependency or changing how the package is built/published |
| `tsconfig.json` | TypeScript compiler config — strict mode on | Rarely |
| `package-lock.json` | Locked dependency versions | Auto-managed by npm, don't hand-edit |

---

## `src/` — the actual source code (edit this, not `dist/`)

| Path | What it is |
|---|---|
| `src/index.ts` | The CLI entry point — wires every scanner together, defines all commands (`scan`, `fix`, `remove-dependency`, `clean`, `config`), handles the existence check, error handling, and the pre-clone confirmation flow |
| `src/report.ts` | Formats every scanner's output into the human-readable report — severity labels (CRITICAL/HIGH/MODERATE/LOW), the `hasFindings`/`hasHighRiskFindings` logic that CI gating depends on |
| `src/config.ts` | Reads/writes `.codevet/config.json` (per-project enable/disable toggles) — **only trusted for a project the user owns locally**, never for an untrusted clone (see the security note in the file itself) |
| `src/resolveTarget.ts` | Turns CLI args into an actual scan target — handles unquoted multi-word paths, git/GitHub URL cloning, persisting or discarding a clone, the provenance marker `codevet clean` relies on |
| `src/promptConfirm.ts` | The y/N confirmation prompt (built on Node's own `readline`, no extra dependency) |
| `src/detectors/detectStack.ts` | Looks for `package.json`/`requirements.txt`/`build.gradle`/`Podfile` to identify which stack(s) are present |
| `src/fixLibrary/templates.ts` | **Single source of truth** for every suggested-fix code snippet (helmet, CORS, rate limiter, account backoff, error handler, password hashing, JWT, validation, file upload, `.env.example`, RLS-enable SQL, the CI workflow template, the pre-commit hook template) |
| `src/scanners/gitleaksScanner.ts` | Wraps the vendored `gitleaks` binary — secret detection |
| `src/scanners/npmAuditScanner.ts` | Wraps `npm audit` — Node dependency vulnerabilities |
| `src/scanners/pipAuditScanner.ts` | Wraps `pip-audit` — Python dependency vulnerabilities (supports both `requirements.txt` and `pyproject.toml`) |
| `src/scanners/bearerScanner.ts` | Wraps the vendored `bearer` binary — personal data flow (PII logging, etc.); no native Windows build, handled gracefully |
| `src/scanners/hygieneScanner.ts` | CodeVet's own heuristic scanner — missing middleware, error leaks, Supabase RLS gaps — maps every finding to a real fix template |
| `src/scanners/npmFixActions.ts` | Backs the `fix` and `remove-dependency` commands |

**Every scanner file follows the same shape:** wraps a real, trusted
external tool (never reimplements detection logic), exports a function
returning normalized findings, and throws a specific error class when the
tool genuinely fails — never silently returns an empty result on failure.
Follow this pattern for any new scanner (see `CONTRIBUTING.md`).

---

## `dist/` — compiled output (generated, never hand-edit)

Produced by `npm run build` (`tsc`). This is what actually ships when
someone installs the package — `src/` is only needed by contributors
editing the tool. If you edit anything in `dist/` directly, it'll be
silently overwritten on the next build.

---

## `templates/` — human-browsable fix-library files (generated)

A plain, readable copy of every fix template from `src/fixLibrary/templates.ts`,
regenerated via `npm run generate-templates`. This exists so someone can
browse the actual fix code on GitHub without reading TypeScript string
literals. **Never hand-edit files under here** — edit `templates.ts` and
regenerate. `scripts/generateTemplates.mjs` is what performs the generation.

---

## `scripts/` — standalone Node scripts (not part of the compiled CLI)

| File | What it does |
|---|---|
| `scripts/postinstall.mjs` | Runs automatically after `npm install` — downloads the correct `gitleaks`/`bearer` binary for the installing machine's OS/architecture. Skips `bearer` cleanly on Windows (no native build exists) |
| `scripts/generateTemplates.mjs` | Regenerates `templates/` from `src/fixLibrary/templates.ts` |
| `scripts/postPrComment.mjs` | Used by `action.yml` — formats a JSON scan report as Markdown and posts it as a PR comment via the GitHub REST API |

---

## `tests/` — the automated test suite

Run with `npm test`. Uses Node's built-in test runner (`node:test`), no
external test framework — one less dependency to justify. Each scanner
that can be tested without a real network call has real, reproduced test
cases (a vulnerable fixture, a clean fixture) — not mocked data.

| File | Covers |
|---|---|
| `tests/config.test.ts` | `.codevet/config.json` load/save, `.gitignore` auto-append |
| `tests/detectStack.test.ts` | Stack detection across Node/Python/multi-stack/unrecognized projects |
| `tests/hygieneScanner.test.ts` | Every hygiene check — helmet, error leaks, CORS, Supabase RLS (both Express and non-Express projects) |
| `tests/fixtures/` | Present but currently empty — tests build fixtures inline (temp directories created and torn down per-test) rather than static files here. Kept as the conventional place to add static fixtures if a future test needs one |

---

## `docs/` — reference documentation

| File | What it is |
|---|---|
| `docs/HELP.md` | The complete command reference — every flag, every subcommand, kept in sync with actual `--help` output |
| `docs/ABOUT.md` | Project philosophy, why it exists, explicit scope boundaries |
| `docs/SECURITY-CHECKLIST.md` | The full severity-annotated security checklist CodeVet's automated checks are built around, including what stays a human judgment call |

---

## `.claude/`, `.cursor/`, `.opencode/` — Agent Skill packaging

Each contains a thin `skills/codevet/SKILL.md` that just points back to
the canonical `AGENTS.md` at the repo root — so there's exactly one place
the actual instructions live, no risk of the copies drifting out of sync.
This is what lets someone ask their AI coding CLI to "scan this with
CodeVet" directly in conversation.

---

## `bin/vendor/` (not committed — created by `postinstall.mjs`)

Where the downloaded `gitleaks`/`bearer` binaries actually live after
install. Gitignored, platform-specific, regenerated by every fresh
`npm install`.
