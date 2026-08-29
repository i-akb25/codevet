# CodeVet — Agent Skill

This file is the canonical instructions for using CodeVet from inside an
AI coding CLI (Claude Code, Cursor, OpenCode, Codex, etc.). Every CLI-specific
skill file in this repo (`.claude/skills/codevet/SKILL.md`,
`.cursor/skills/codevet/SKILL.md`, etc.) just points back here — this is
the one place the actual instructions live.

## What this skill does

Lets you ask the agent to vet a project's security directly in
conversation — "scan this repo with CodeVet," "check this project for
leaked secrets," "is this safe to deploy" — without leaving the coding CLI
to run a separate tool.

## When to use it

- Before committing, pushing, or opening a PR
- Before deploying to production
- Before cloning and trusting a third-party repo
- When asked to "check for security issues" or "vet this code"

## How to run it

```bash
npx codevet scan                          # scan the current project
npx codevet scan <path>                   # scan a specific folder
npx codevet scan <git-url>                # review a repo before keeping a clone
npx codevet scan --json report.json       # machine-readable output
npx codevet scan --fail-on-high-risk      # non-zero exit if anything critical/high is found
```

If `codevet` isn't installed yet, `npx codevet` fetches and runs it
without a global install.

## Interpreting results

CodeVet reports four categories, each with a severity:

- **CRITICAL** — fix before anyone else touches this code (e.g. a
  Supabase table with no Row Level Security)
- **HIGH** — fix before launch (e.g. missing rate limiting on auth routes,
  a leaked secret, a known-vulnerable dependency)
- **MODERATE** — real, but rarely the sole cause of an incident on its own
  (e.g. missing security headers)
- **LOW** — worth doing, not urgent

Every finding includes a `Suggested fix` with real, working code — apply
it directly rather than researching the fix from scratch. When a finding
has a `Verify:` note, treat that as a genuine caveat: some checks are
heuristic and can be wrong for unusual setups (e.g. the "no validation
library" check can't see hand-written validation).

## What NOT to do with this skill

- Don't silently "fix" every finding without explaining it to the user
  first — some are false positives, and blindly applying every suggested
  fix (especially `codevet remove-dependency`) can break a working app
- Don't treat a clean scan as a guarantee — CodeVet checks known,
  disclosed issues in specific categories, not a full security audit
- Don't run `codevet fix --force` or `codevet remove-dependency` without
  explicit user confirmation — these modify the project's dependencies

## Related commands

- `codevet fix` — safely upgrade flagged dependencies within existing semver ranges
- `codevet fix --force` — allow major-version upgrades (may need code changes after)
- `codevet remove-dependency <name>` — explicitly uninstall a flagged package (not the same as fixing it)
- `codevet clean <path>` — remove a repo CodeVet previously cloned and kept
- `codevet config disable <secrets|dependencies|hygiene|data-flow|all>` — turn off a specific check for this project
