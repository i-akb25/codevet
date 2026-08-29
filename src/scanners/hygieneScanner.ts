import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import fg from "fast-glob";
import { FIX_TEMPLATES, type FixTemplate } from "../fixLibrary/templates.js";

export interface HygieneFinding {
  id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "moderate" | "low";
  /** Every hygiene check is pattern/heuristic-based (package.json presence,
   *  regex scans, not a real AST parse) — this note explains the specific
   *  way THIS check can be wrong for an unusual setup, kept separate from
   *  severity so "how bad is this" and "how sure are we" aren't conflated. */
  verifyNote?: string;
  fix: FixTemplate;
}

/**
 * These are heuristic checks — package.json presence and regex scans, not
 * a real AST parse. That means false negatives are possible (a helmet-like
 * setup written by hand instead of the package would be missed) and
 * "advisory" findings can be wrong for unusual architectures. Marked
 * explicitly per-finding rather than presented with false confidence.
 */
export async function runHygieneScan(projectRoot: string): Promise<HygieneFinding[]> {
  const packageJsonPath = join(projectRoot, "package.json");
  if (!existsSync(packageJsonPath)) return [];

  const packageJson = JSON.parse(await readFile(packageJsonPath, "utf-8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const allDeps = { ...packageJson.dependencies, ...packageJson.devDependencies };
  const hasDep = (name: string) => Boolean(allDeps[name]);

  const findings: HygieneFinding[] = [];

  // RLS check is independent of Express — Supabase is at least as common
  // with Next.js/other frontends as with an Express backend, and skipping
  // it here would silently miss exactly the audience most likely to use
  // Supabase directly from the client.
  findings.push(...(await runSupabaseRlsScan(projectRoot)));

  // Only run Express-specific checks on projects that actually use Express
  // — otherwise every finding below would be a guaranteed false positive
  // on a non-Express project.
  if (!hasDep("express")) return findings;

  if (!hasDep("helmet")) {
    findings.push({
      id: "missing-helmet",
      title: "No security headers configured",
      description:
        "helmet isn't installed — your responses have no protection against clickjacking, MIME-sniffing, or several XSS vectors.",
      severity: "moderate",
      verifyNote:
        "Defense-in-depth, not usually directly exploitable on its own — real risk, but rarely the single point of failure in an incident.",
      fix: FIX_TEMPLATES.helmet,
    });
  }

  if (!hasDep("express-rate-limit")) {
    findings.push({
      id: "missing-rate-limit",
      title: "No rate limiting found",
      description:
        "express-rate-limit isn't installed — login and other sensitive endpoints have no protection against brute-force or spam.",
      severity: "high",
      verifyNote: "Directly exploitable if auth routes exist with no other rate-limiting layer (e.g. a reverse proxy).",
      fix: FIX_TEMPLATES.rateLimit,
    });
  }

  const hasValidationLib = hasDep("zod") || hasDep("joi") || hasDep("yup");
  if (!hasValidationLib) {
    findings.push({
      id: "missing-validation",
      title: "No schema validation library found",
      description:
        "Neither zod, joi, nor yup is installed. If requests are validated by hand, this is likely a false positive — worth a manual check either way.",
      severity: "moderate",
      verifyNote:
        "This check only looks for known validation libraries — hand-written validation is common and invisible to it. Confirm manually before treating this as real.",
      fix: FIX_TEMPLATES.validation,
    });
  }

  const sourceFindings = await scanSourceForPatterns(projectRoot);
  findings.push(...sourceFindings);

  return findings;
}

/**
 * Supabase-specific check: scans .sql migration files for CREATE TABLE
 * statements with no matching ENABLE ROW LEVEL SECURITY in the same file.
 * This is a best-effort STATIC check only — it cannot see tables created
 * via the Supabase dashboard UI or RLS enabled outside migration files.
 * Rated CRITICAL severity (a real missing-RLS table is the single most
 * common cause of a drained/defaced Supabase app), with verifyNote always
 * set to keep that static-check limitation visible alongside the severity.
 */
export async function runSupabaseRlsScan(projectRoot: string): Promise<HygieneFinding[]> {
  const sqlFiles = await fg(["**/*.sql"], {
    cwd: projectRoot,
    absolute: true,
    ignore: ["**/node_modules/**"],
  });

  if (sqlFiles.length === 0) return [];

  const findings: HygieneFinding[] = [];

  for (const sqlFile of sqlFiles) {
    const content = await readFile(sqlFile, "utf-8").catch(() => "");
    const tableMatches = [...content.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?["`]?(\w+)["`]?/gi)];

    for (const match of tableMatches) {
      const tableName = match[1];
      const rlsPattern = new RegExp(
        `ALTER TABLE\\s+["\`]?${tableName}["\`]?\\s+ENABLE ROW LEVEL SECURITY`,
        "i",
      );
      if (!rlsPattern.test(content)) {
        findings.push({
          id: `supabase-rls-missing-${tableName}`,
          title: `Table '${tableName}' may be missing Row Level Security`,
          description: `Found in ${sqlFile.replace(projectRoot, "").replace(/^[/\\]/, "")} — no matching 'ENABLE ROW LEVEL SECURITY' for this table in the same file. Without RLS, the public anon key can read and write this table directly — this is the single most common cause of drained or defaced Supabase-backed apps.`,
          severity: "critical",
          verifyNote:
            "Static check only — it cannot see RLS enabled via the Supabase dashboard UI or outside migration files. Verify directly in the dashboard before treating a clean result as certain.",
          fix: FIX_TEMPLATES.rlsEnable,
        });
      }
    }
  }

  return findings;
}

async function scanSourceForPatterns(projectRoot: string): Promise<HygieneFinding[]> {
  const findings: HygieneFinding[] = [];

  const files = await fg(["**/*.js", "**/*.ts"], {
    cwd: projectRoot,
    absolute: true,
    ignore: [
      "**/node_modules/**",
      "**/.next/**",
      "**/dist/**",
      "**/build/**",
      "**/*.test.*",
      "**/*.spec.*",
    ],
  });

  let corsWildcardFound = false;
  let errorLeakFound = false;

  for (const file of files) {
    const content = await readFile(file, "utf-8").catch(() => "");

    if (!corsWildcardFound && /cors\s*\(\s*\)|origin\s*:\s*['"]\*['"]/.test(content)) {
      corsWildcardFound = true;
    }

    // Heuristic: sending err.stack or err.message directly in a response
    // body is a real, specific leak pattern — not "any error handling."
    // Matches res.json(...) and the more common res.status(500).json(...).
    if (
      !errorLeakFound &&
      /res(\.status\([^)]*\))?\.(json|send)\([^)]*(err(or)?\.(stack|message))/.test(content)
    ) {
      errorLeakFound = true;
    }

    if (corsWildcardFound && errorLeakFound) break;
  }

  if (corsWildcardFound) {
    findings.push({
      id: "cors-wildcard",
      title: "CORS may be wide open",
      description:
        "Found cors() with no origin restriction, or an explicit '*' origin — any website can currently read responses from this API.",
      severity: "high",
      verifyNote: "Pattern-based match — confirm the actual runtime config, since environment-specific overrides won't show here.",
      fix: FIX_TEMPLATES.cors,
    });
  }

  if (errorLeakFound) {
    findings.push({
      id: "error-leak",
      title: "Error response may leak internals",
      description:
        "Found a response that sends err.stack or err.message directly to the client — this can expose file paths, internal logic, or raw database errors.",
      severity: "high",
      verifyNote: "Confirmed by matching an actual response-sending pattern, not just the presence/absence of a library — lower false-positive risk than the other checks here.",
      fix: FIX_TEMPLATES.errorHandler,
    });
  }

  return findings;
}
