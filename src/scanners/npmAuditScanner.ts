import { execa } from "execa";
import { existsSync } from "node:fs";
import { join } from "node:path";

export interface DependencyFinding {
  packageName: string;
  severity: "critical" | "high" | "moderate" | "low";
  /** A package can be flagged by more than one advisory at once — confirmed
   *  in real testing (axios 1.8.2 had 4 separate advisories). Surface all
   *  of them, not just the first. */
  advisories: Array<{ title: string; url?: string; severity: string }>;
  fixAvailable: string | false;
  isDirect: boolean;
}

export class NpmAuditScanFailedError extends Error {
  constructor(reason: string) {
    super(
      `npm audit did not actually run: ${reason}. This is being reported as a failure rather than "no vulnerabilities" — a scan that never ran is not the same as a clean result.`,
    );
    this.name = "NpmAuditScanFailedError";
  }
}

interface NpmAuditVulnerability {
  name: string;
  severity: "critical" | "high" | "moderate" | "low";
  isDirect: boolean;
  via: Array<string | { title: string; url?: string; severity?: string }>;
  fixAvailable: boolean | { name: string; version: string };
}

interface NpmAuditReport {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  // npm audit --json emits valid JSON even on failure — shaped like this
  // instead of having a `vulnerabilities` key. Confirmed in testing (a
  // broken/missing lockfile produces exactly this shape, exit code 1).
  // Silently returning [] here would report a failed scan as "clean",
  // the same class of bug found and fixed in the bearer wrapper.
  error?: { code: string; summary: string; detail?: string };
}

/**
 * Runs a real npm audit against package.json/package-lock.json. This checks
 * against npm's published advisory database (known, disclosed CVEs) — it
 * does NOT detect novel malware or unpublished zero-days. That distinction
 * matters and should stay visible in the report, not be implied away.
 *
 * If no lockfile exists, we generate one with `--package-lock-only
 * --ignore-scripts` — this resolves the dependency tree WITHOUT installing
 * any package or running any install/postinstall script. That matters for
 * scanning an untrusted repo (e.g. before a URL-clone confirmation): a
 * normal `npm install` would execute arbitrary scripts from every
 * dependency before we ever get to look at the results.
 */
export async function runNpmAuditScan(
  projectRoot: string,
): Promise<DependencyFinding[]> {
  const packageJsonPath = join(projectRoot, "package.json");
  if (!existsSync(packageJsonPath)) {
    return [];
  }

  const lockfilePath = join(projectRoot, "package-lock.json");
  if (!existsSync(lockfilePath)) {
    const lockResult = await execa(
      "npm",
      ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
      { cwd: projectRoot, reject: false },
    );
    // If lockfile generation itself failed, npm audit below will fail too
    // (ENOLOCK) — no point running it, and the error is clearer here.
    if (lockResult.exitCode !== 0 && !existsSync(lockfilePath)) {
      throw new NpmAuditScanFailedError(
        `could not generate a package-lock.json (${lockResult.stderr.split("\n")[0] || "unknown error"})`,
      );
    }
  }

  const result = await execa("npm", ["audit", "--json"], {
    cwd: projectRoot,
    reject: false, // npm audit exits non-zero when it finds vulnerabilities — expected
  });

  let report: NpmAuditReport;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    // Genuinely unparseable output (not even npm's own error JSON shape)
    // — a real failure, not a clean result.
    throw new NpmAuditScanFailedError(
      result.stderr.split("\n")[0] || "npm audit produced no readable output",
    );
  }

  if (report.error) {
    throw new NpmAuditScanFailedError(`${report.error.code}: ${report.error.summary}`);
  }

  if (!report.vulnerabilities) return [];

  return Object.values(report.vulnerabilities).map((v) => {
    const advisories = v.via
      .filter(
        (entry): entry is { title: string; url?: string; severity?: string } =>
          typeof entry !== "string",
      )
      .map((entry) => ({
        title: entry.title,
        url: entry.url,
        severity: entry.severity ?? v.severity,
      }));

    return {
      packageName: v.name,
      severity: v.severity,
      advisories:
        advisories.length > 0
          ? advisories
          : [{ title: `Known vulnerability in ${v.name}`, severity: v.severity }],
      fixAvailable:
        typeof v.fixAvailable === "object"
          ? `${v.fixAvailable.name}@${v.fixAvailable.version}`
          : v.fixAvailable
            ? "Run `npm audit fix`"
            : false,
      isDirect: v.isDirect,
    };
  });
}
