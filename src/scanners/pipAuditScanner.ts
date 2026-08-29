import { execa } from "execa";
import { existsSync } from "node:fs";
import { join } from "node:path";

export interface PythonDependencyFinding {
  packageName: string;
  installedVersion: string;
  /** PyPA's advisory database (unlike npm's GHSA-based one) does not
   *  include a severity rating — inventing one here would be exactly the
   *  kind of fake-confidence this project avoids. Every finding is shown
   *  with equal visual weight and a note to assess severity from the
   *  advisory text/CVE itself. */
  advisories: Array<{ id: string; description: string; fixVersions: string[] }>;
}

export class PipAuditScanFailedError extends Error {
  constructor(reason: string) {
    super(
      `pip-audit did not actually run: ${reason}. This is being reported as a failure rather than "no vulnerabilities" — a scan that never ran is not the same as a clean result.`,
    );
    this.name = "PipAuditScanFailedError";
  }
}

export class PipAuditNotInstalledError extends Error {
  constructor() {
    super(
      "pip-audit isn't installed on this machine, so the Python dependency check couldn't run. Install it with 'pip install pip-audit' — secrets, hygiene, and other checks are unaffected.",
    );
    this.name = "PipAuditNotInstalledError";
  }
}

interface PipAuditVuln {
  id: string;
  fix_versions: string[];
  description: string;
}
interface PipAuditDependency {
  name: string;
  version: string;
  vulns: PipAuditVuln[];
}
interface PipAuditReport {
  dependencies: PipAuditDependency[];
}

function findRequirementsFile(projectRoot: string): string | null {
  for (const name of ["requirements.txt", "pyproject.toml"]) {
    const path = join(projectRoot, name);
    if (existsSync(path)) return path;
  }
  return null;
}

/**
 * Runs real pip-audit against requirements.txt or pyproject.toml, checking
 * PyPA's published advisory database (known, disclosed CVEs) — same
 * "known issues only, not a malware/zero-day scanner" honesty as the npm
 * audit wrapper. Returns [] (not an error) if no Python project is
 * detected — that's a real "nothing to check" case, not a failure.
 */
export async function runPipAuditScan(
  projectRoot: string,
): Promise<PythonDependencyFinding[]> {
  const reqFile = findRequirementsFile(projectRoot);
  if (!reqFile) return [];

  const isRequirementsTxt = reqFile.endsWith("requirements.txt");
  const args = isRequirementsTxt
    ? ["-r", reqFile, "-f", "json"]
    : [projectRoot, "-f", "json"]; // pyproject.toml: pip-audit reads the project dir directly

  const result = await execa("pip-audit", args, { cwd: projectRoot, reject: false });

  if (result.failed && result.exitCode === undefined) {
    // execa couldn't even spawn the process — pip-audit isn't installed.
    throw new PipAuditNotInstalledError();
  }

  let report: PipAuditReport;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    // Confirmed in testing: a genuine pip-audit failure (e.g. an
    // unresolvable requirement) produces NO valid JSON on stdout and
    // writes errors to stderr instead — unlike npm audit, there's no
    // ambiguous "valid JSON shaped like an error" case here, so any
    // parse failure means the scan genuinely didn't complete.
    throw new PipAuditScanFailedError(
      result.stderr.split("\n").find((l) => l.trim().length > 0) || "no readable output produced",
    );
  }

  if (!report.dependencies) return [];

  const findings: PythonDependencyFinding[] = [];
  for (const dep of report.dependencies) {
    if (dep.vulns.length === 0) continue;
    findings.push({
      packageName: dep.name,
      installedVersion: dep.version,
      advisories: dep.vulns.map((v) => ({
        id: v.id,
        description: v.description.split("\n")[0].slice(0, 200),
        fixVersions: v.fix_versions,
      })),
    });
  }

  return findings;
}
