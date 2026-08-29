import { execa } from "execa";
import { readFile, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
// This file lives at dist/scanners/gitleaksScanner.js at runtime, whether
// CodeVet is run standalone (cloned repo) or installed as a dependency
// inside another project's node_modules/codevet/ — the relative path up
// to the package root is identical either way, so this resolves correctly
// in both installation modes.
const PACKAGE_ROOT = join(__dirname, "..", "..");
const GITLEAKS_BIN = join(
  PACKAGE_ROOT,
  "bin",
  "vendor",
  process.platform === "win32" ? "gitleaks.exe" : "gitleaks",
);
const RULES_CONFIG = join(PACKAGE_ROOT, ".gitleaks.toml");

export interface SecretFinding {
  ruleId: string;
  description: string;
  file: string;
  line: number;
}

export class GitleaksBinaryMissingError extends Error {
  constructor() {
    super(
      `gitleaks binary not found at ${GITLEAKS_BIN}. This usually means the postinstall step didn't run — try 'npm install' again inside the codevet package.`,
    );
    this.name = "GitleaksBinaryMissingError";
  }
}

export async function runGitleaksScan(
  projectRoot: string,
): Promise<SecretFinding[]> {
  if (!existsSync(GITLEAKS_BIN)) {
    throw new GitleaksBinaryMissingError();
  }

  const reportPath = join(projectRoot, ".codevet-gitleaks-report.json");

  try {
    await execa(
      GITLEAKS_BIN,
      [
        "detect",
        "--source",
        projectRoot,
        "--config",
        RULES_CONFIG,
        "--report-format",
        "json",
        "--report-path",
        reportPath,
        "--no-banner",
        "--no-git",
      ],
      { reject: false },
    );

    const raw = await readFile(reportPath, "utf-8").catch(() => "[]");
    const parsed = JSON.parse(raw) as Array<{
      RuleID: string;
      Description: string;
      File: string;
      StartLine: number;
    }>;

    const findings = parsed.map((entry) => ({
      ruleId: entry.RuleID,
      description: entry.Description,
      file: entry.File,
      line: entry.StartLine,
    }));

    return await postProcess(findings, projectRoot);
  } finally {
    await unlink(reportPath).catch(() => {});
  }
}

/**
 * Two real issues found in live Windows testing, fixed here rather than in
 * the raw gitleaks output:
 *
 * 1. Duplicate findings — the same (file, line, rule) can be reported more
 *    than once by gitleaks when overlapping rules both match; we only want
 *    to show it once.
 *
 * 2. .env files legitimately contain real secret values locally — that's
 *    the whole point of .env. The actual risk isn't the values, it's
 *    whether the file is protected by .gitignore. If it IS gitignored, its
 *    contents can never reach a commit, so flagging them as "leaked" is a
 *    false positive. If it's NOT gitignored, that's a real and more
 *    important problem worth its own clear finding.
 */
async function postProcess(
  findings: SecretFinding[],
  projectRoot: string,
): Promise<SecretFinding[]> {
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.file}:${f.line}:${f.ruleId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const isGitRepo = existsSync(join(projectRoot, ".git"));
  if (!isGitRepo) return deduped;

  const envIsIgnored = await execa("git", ["check-ignore", ".env"], {
    cwd: projectRoot,
    reject: false,
  }).then((r) => r.exitCode === 0);

  if (envIsIgnored) {
    // .env is protected — drop findings whose file is exactly .env, since
    // its contents can't leak through git.
    return deduped.filter((f) => !/(^|[/\\])\.env$/.test(f.file));
  }

  // .env exists and is NOT gitignored — replace any per-line findings
  // inside it with one clear, higher-signal warning instead of dumping
  // every value found inside it.
  const hasEnvFindings = deduped.some((f) => /(^|[/\\])\.env$/.test(f.file));
  const withoutEnvDetails = deduped.filter(
    (f) => !/(^|[/\\])\.env$/.test(f.file),
  );

  if (hasEnvFindings) {
    withoutEnvDetails.push({
      ruleId: "env-file-not-gitignored",
      description:
        ".env exists and contains real values, but is NOT excluded by .gitignore — every credential in it can end up committed to git history.",
      file: ".env",
      line: 1,
    });
  }

  return withoutEnvDetails;
}
