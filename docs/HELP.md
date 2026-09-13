# Help

## Installing

```
npm install -g codevet-cli          # global install, gives you the `codevet` command anywhere
# or
npm install --save-dev codevet-cli  # install into a specific project — after this, `npx codevet` resolves to it locally
```

**One-off use, no install:** `npx codevet-cli@latest scan` — the `-cli`
suffix matters here specifically. A different, unrelated package is
published under the bare name `codevet`; `npx codevet` with nothing
installed locally will fetch that one instead.

**pnpm or Yarn workspace:** don't `npm install codevet-cli` inside one —
npm's resolver can crash on pnpm's symlinked `node_modules`. Use
`pnpm dlx codevet-cli scan` or `npx codevet-cli@latest scan` instead,
neither of which touches the workspace's dependency tree.

## Scanning

```
codevet scan                    # scans the current directory
codevet scan ./some/folder      # scans a specific local folder
codevet scan https://github.com/user/repo   # clones and scans a repo before you keep it
```

If your path has spaces and you forget to quote it, CodeVet will try to
rejoin it automatically and tell you it did so. Quoting the path yourself
(`codevet scan "C:\My Projects\app"`) is still the reliable way.

### Options

```
codevet scan --no-secrets        # skip the secret-scanning check, this run only
codevet scan --no-dependencies   # skip the dependency-vulnerability check, this run only
```

## Scanning a repository before deciding to keep it

```
codevet scan https://github.com/someone/some-repo
```

- Always asks before keeping anything, regardless of the result — a clean
  scan means "the checks above found nothing," not "this is safe."
  CodeVet only checks for known secrets, dependency CVEs, and a small set
  of hygiene patterns, never malware or novel logic.
- Answering no discards it completely — nothing is left behind.
- Pass `--keep` to skip the prompt and keep it automatically, for
  CI/scripted use: `codevet scan <url> --keep`.

## Turning scanners on/off for a project

```
codevet config status                  # see what's currently enabled
codevet config disable dependencies    # turn off dependency scanning for this project
codevet config enable secrets          # turn a scanner back on
codevet config disable all             # turn everything off
```

This is stored in `.codevet/config.json` inside the project and only
applies to a project you're scanning locally — it has no effect when
reviewing a freshly-cloned, not-yet-trusted repository (see `TERMS.md` for
why: a malicious repo can't ship a config that disables its own scan).

## Removing a repository CodeVet cloned and kept

```
codevet clean ./some-repo-you-kept
codevet clean ./some-repo-you-kept --yes   # skip the confirmation prompt
```

Checks for a marker CodeVet writes when it persists a clone, so you get a
clear warning if you point it at a folder it didn't actually create.
Refuses outright on anything that resolves to a root or home directory.

## Fixing flagged dependencies

```
codevet fix                    # safe upgrade — only within your existing semver ranges
codevet fix --force            # allow major-version upgrades (may include breaking changes)
```

This runs the real `npm audit fix` under the hood. If a package is pinned
to an exact version with no `^`/`~`, the safe mode often can't touch it —
`--force` is what breaks out of that, at the cost of possibly needing code
changes afterward.

## Removing a specific flagged dependency entirely

```
codevet remove-dependency axios
codevet remove-dependency axios --yes   # skip the confirmation prompt
```

**This is different from `fix`.** It uninstalls the package outright — use
this only when you're sure the flagged package isn't actually used
anywhere in your code, not as a shortcut around fixing something you
depend on.

## Getting more detail on any command

```
codevet --help
codevet scan --help
codevet config --help
```

## Running automatically on every PR (GitHub Action)

Add this to `.github/workflows/codevet.yml` in your repo:

```yaml
name: CodeVet
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: codevet/codevet@v1
```

This runs all four checks (secrets, dependencies, hygiene, personal data
flow) on every PR and posts the results as a comment directly on the PR —
no separate dashboard, no account. By default the check fails if any
secret or high/critical dependency/data-flow finding is present; set
`fail-on-high-risk: "false"` in the action's `with:` block if you want it
advisory-only instead.

## Personal data flow scanning (via bearer)

```
codevet scan --no-data-flow    # skip this check for this run only
codevet config disable data-flow
```

Catches things pattern-based scanning can't — like logging a password or
SSN, or sending PII to a third-party endpoint — by tracing where sensitive
values actually flow through your code, not just matching text patterns.

**Platform note:** bearer has no native Windows build. On Windows,
CodeVet's other three checks (secrets, dependencies, hygiene) work
normally, but this specific check is unavailable — you'll see a clear
message explaining why rather than a silent gap. WSL is a workaround if
you need this check on Windows.

## A known limitation: pnpm-managed projects

Dependency scanning is skipped (not failed) on projects using pnpm
(detected via `pnpm-lock.yaml` or `node_modules/.pnpm`). This isn't a
CodeVet limitation — it's a real, confirmed bug in npm itself: npm's own
dependency resolver crashes with an internal error when it encounters
pnpm's symlink structure in `node_modules`. Run `pnpm audit` directly for
these projects; secrets, hygiene, and data-flow checks are unaffected.

## Reading the coverage and verdict lines

Every scan ends with two things:

```
Coverage:
  Secrets:       completed
  Dependencies:  completed
  Hygiene:       completed
  Data flow:     skipped

Verdict: INCOMPLETE
```

`Coverage` shows exactly which checks actually ran — `completed`,
`skipped` (disabled by config, or unavailable like Bearer on Windows), or
`failed` (attempted but genuinely errored, e.g. a network issue). The
`Verdict` is one of:

- **PASS** — every check completed, nothing found
- **PASS WITH WARNINGS** — everything completed, only moderate/low findings
- **BLOCKED** — a real critical/high finding was found (takes priority
  over everything else, since a real problem matters more than a
  coverage gap)
- **INCOMPLETE** — one or more checks didn't fully run, so the picture
  isn't complete, even if nothing was found in what did run

A skipped or failed check never gets silently treated as equivalent to a
clean result — that distinction is the entire point of this line.

## Machine-readable output (for CI/tooling)

```
codevet scan --json report.json         # also writes a JSON report alongside the normal output
codevet scan --fail-on-high-risk         # exits with a non-zero code if anything serious is found
```

## Installing into a pnpm or Yarn workspace

Don't run `npm install codevet-cli` (or `npm i codevet-cli`) inside a pnpm-
or Yarn-managed monorepo — npm's own dependency resolver can crash trying
to interpret pnpm's symlinked `node_modules` structure (a real, confirmed
npm bug, not something CodeVet causes). Use `npx` instead, which doesn't
touch the workspace's dependency tree at all:

```
npx codevet-cli scan .
```

If you want CodeVet available as an actual dev dependency in a pnpm
workspace, use pnpm itself to install it: `pnpm add -D codevet-cli`.

## Something not working?

Check `TROUBLESHOOTING.md` if it exists in this repo, or open an issue —
unless it's a security vulnerability, in which case see `SECURITY.md`
instead of a public issue.
