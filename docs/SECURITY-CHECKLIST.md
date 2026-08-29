# SECURITY-CHECKLIST.md — Severity-annotated

**CRITICAL** = fix before anyone else touches this code. **HIGH** = fix before
launch. **MODERATE** = real, but rarely the sole cause of an incident —
schedule it, don't panic. **LOW** = worth doing, not urgent.

Items marked **[CodeVet]** are checked automatically by `codevet scan`.
Everything else stays a human judgment call — no scanner replaces review
for business logic, authorization correctness, or the legal/business
items at the bottom.

---

## Security (highest priority)

| Item | Severity | Automated? |
|---|---|---|
| No hardcoded API keys/secrets/credentials — use env vars | **CRITICAL** | **[CodeVet]** gitleaks |
| `.env` not gitignored (real values could reach git history) | **CRITICAL** | **[CodeVet]** |
| Supabase: Row Level Security enabled on every table | **CRITICAL** | **[CodeVet]** (static check — verify in dashboard too) |
| Supabase: service role key never in client-side code | **CRITICAL** | **[CodeVet]** gitleaks |
| Exposed `.env` files, `.git` folders, or admin routes in production | HIGH | Manual — deployment config |
| SQL injection / XSS / CSRF protection in place | HIGH | Manual — needs code review |
| No rate limiting on auth routes (login/signup/reset) | HIGH | **[CodeVet]** |
| CORS wide open (`*`) | HIGH | **[CodeVet]** (pattern match — confirm runtime config) |
| Error responses leak stack traces / internal details | HIGH | **[CodeVet]** |
| Passwords hashed (bcrypt/argon2), never plaintext | HIGH | Manual — CodeVet can't verify runtime behavior |
| Auth flows tested: session expiry, token refresh, RBAC | HIGH | Manual |
| Dependencies scanned for known vulnerabilities | HIGH | **[CodeVet]** npm audit |
| No security headers configured (helmet) | MODERATE | **[CodeVet]** |
| No schema validation library detected | MODERATE | **[CodeVet]** (false-positive-prone — hand-written validation is invisible to this check) |

## Code & architecture

| Item | Severity | Automated? |
|---|---|---|
| Every API route checks who's calling (auth check present) | HIGH | Manual — AI-generated routes often skip this |
| Test accounts / seed data / debug pages removed before launch | HIGH | Manual |
| Error handling doesn't leak internals to users | HIGH | **[CodeVet]** (same check as above) |
| No leftover `console.log`s, debug routes, or test data | LOW | Manual |
| Environment configs separated (dev/staging/prod) | MODERATE | Manual |
| Remove unused code, commented-out blocks, dead dependencies | LOW | Manual |

## Data & backend

| Item | Severity | Automated? |
|---|---|---|
| Input validation on the server (never trust the client) | HIGH | Manual + **[CodeVet]** validation-library check |
| Rate limiting on anything that costs money (AI calls, email, login) | HIGH | Partial — **[CodeVet]** checks auth routes; other cost-bearing endpoints need manual review |
| Database backups configured and tested (can you actually restore?) | HIGH | Manual |
| Migrations are clean and reversible | MODERATE | Manual |

## Deployment & ops

| Item | Severity | Automated? |
|---|---|---|
| Plan for key rotation if one leaks | HIGH | Manual — have the runbook ready before you need it |
| SSL/HTTPS enforced everywhere | HIGH | Manual — deployment/infra config |
| CI/CD or a documented, repeatable deploy process | MODERATE | Manual |
| Monitoring/error tracking set up (Sentry, etc.) | MODERATE | Manual |

## Legal & business

**Not automatable — CodeVet has no visibility into contracts or business
terms.** Still worth having a checklist for, since these cause real pain
when skipped:

| Item | Severity |
|---|---|
| Written contract: scope, deliverables, payment, revision limits | HIGH |
| IP ownership clause — who owns the code once paid? | HIGH |
| Privacy policy / terms of service if collecting user data | HIGH |
| DPDP Act / GDPR / CCPA compliance if applicable to your user base | HIGH |
| Clear statement of what's *not* included (maintenance, hosting, fees) | MODERATE |
| Handover docs: run locally, deploy, env vars, admin access | MODERATE |

## Handover checklist

| Item | Severity |
|---|---|
| All credentials transferred securely, never over Slack/email plaintext | HIGH |
| README with setup instructions | MODERATE |
| You retain no unnecessary access after the project ends | HIGH |

---

## The honest read

If you only have time for the CRITICAL and HIGH rows: that's a legitimate
launch bar for a small project. MODERATE items are real but rarely the
single cause of an incident — schedule them, don't block launch on them.
The two things people skip most and regret most: **security hardening**
(the CRITICAL/HIGH rows above) and **the contract** (Legal & business
section) — if you only fix two categories, make it those.
