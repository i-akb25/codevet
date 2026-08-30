# Contributing to CodeVet

## Before you start

- Check existing issues/PRs first — avoid duplicate work
- For anything beyond a small fix, open an issue to discuss the approach
  before writing code

## Code quality — not allowed in this codebase

- `console.log` left in production code (use structured output through the
  existing report/CLI layers instead)
- TODOs, placeholder implementations, or fake/mocked scan results outside
  of `tests/`
- Commented-out code, dead code, unused imports
- `@ts-ignore` or `as any` used to silence a real type problem instead of
  fixing it
- A "fix" that only handles the reproduction case shown in an issue —
  trace the actual root cause (see the EXDEV cross-drive bug and the
  Windows `unzip` bug in git history for what root-cause fixes look like
  here, versus a narrow patch)

## Engineering standards (please actually follow these)

This project deliberately avoids "vibe coding" — generating code until it
looks like it works. Concretely, that means:

- **Understand the change before writing it.** What does it need to do,
  where does it belong, what existing code should it reuse?
- **Minimum code that correctly solves the problem.** Don't add
  abstraction, config options, or generality a second real use case
  hasn't actually asked for yet.
- **Every dependency must justify itself.** Before adding a package: can
  Node's standard library do this? Is it maintained? Run `npm audit`
  before proposing it — a vulnerability in a *security tool's* own
  dependency tree undermines the whole project (this has already caught
  one proposed dependency during development — see git history).
- **No mock data, no fake functionality.** Every finding shown to a user
  must come from a real scanner run against real test data, not a
  hardcoded example.
- **Type-safe.** Strict TypeScript, no `any`, no unexplained `@ts-ignore`.
- **Test against a real, reproduced scenario**, not just "it compiles."
  If you're fixing a bug, reproduce it first, then verify the fix against
  that reproduction — a regression test, not just a description.

## If you're using an AI coding tool to contribute

CodeVet's own audience uses AI coding tools daily, so this comes up a lot
— the same discipline applies to AI-assisted PRs as to any other:

- Generate only the files the change actually requires — an AI tool
  "helpfully" refactoring unrelated files, renaming things, or reorganizing
  folders outside the scope of the change will be asked to be reverted
- Don't let the AI invent architecture or add a dependency the issue
  didn't call for — if it suggests one, evaluate it against the
  Dependencies rule above before including it in the PR
  A locked pattern in this codebase (e.g. scanners always wrap a real
  external tool, never reimplement detection) should not get silently
  "improved" away because a different approach seemed cleaner
- Ask for the complete implementation, not `// rest of the code...` or
  `// TODO: implement error handling` — incomplete generated code should
  never reach a PR
- Run the real verification steps below yourself before opening the PR —
  "the AI said it works" is not the same as it actually working against
  real test data, and this project's whole history (see git log) is full
  of cases where something that looked correct had a real bug underneath

## Definition of done

A change is not complete until it is:

- Production-ready (no placeholder or "good enough for now" behavior)
- Type-safe (strict TypeScript, `npx tsc --noEmit` clean)
- Tested against a real, reproduced scenario (not just "it compiles")
- Free of dead code, TODOs, and stray `console.log`
- Passing `npm test` and showing `0 vulnerabilities` from `npm audit`
- Verified with `node dist/index.js scan .` (CodeVet against its own code)

Anything less is incomplete, regardless of how small the change looks.

## Setting up locally

```
git clone https://github.com/i-akb25/codevet.git
cd codevet
npm install
npm run build
node dist/index.js scan .   # should complete cleanly against this repo itself
```

## Before opening a PR

```
npm run build          # must compile with zero TypeScript errors
npm audit               # must show 0 vulnerabilities before you add a dependency
node dist/index.js scan .   # sanity-check CodeVet against its own code
```

## Adding a new scanner

Each scanner lives in `src/scanners/`, wraps a real, trusted external tool
(never reimplements detection logic from scratch), and exports a function
returning normalized findings — follow the shape of
`src/scanners/gitleaksScanner.ts` or `npmAuditScanner.ts` as a template.

## A known, accepted noise source in CodeVet's own self-scan

When CodeVet scans its own repo, Bearer's data-flow check flags roughly
70 LOW-severity "logger leak" findings across `src/index.ts` and
`src/report.ts`. This is expected, not a bug: those files' entire job is
printing scan results to the terminal — that's the CLI's actual output,
not a leak. This is specific to a CLI tool scanning itself; it does not
affect Bearer's real value for a typical backend app, where
`console.log`-ing a password or SSN genuinely is a problem worth catching.

**A real false positive was found and fixed here, worth knowing about
directly:** `src/fixLibrary/templates.ts` is a library of example code
shown to users (including a variable named `SECRET` correctly read from
`process.env` — the safe pattern we specifically teach). Bearer's static
analysis flagged that as a CRITICAL hardcoded secret before we added
`--skip-path` for fix-library/template directories in
`src/scanners/bearerScanner.ts`. Any new template file added to that
scanner needs to stay covered by that skip-path — verify with
`node dist/index.js scan . --no-secrets --no-dependencies --no-hygiene`
before merging.

## Questions

Open a discussion or issue — this file will grow as real contribution
patterns emerge, rather than trying to anticipate everything upfront.
