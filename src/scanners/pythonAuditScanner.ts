import { execa } from "execa";
import { existsSync } from "node:fs";
import { join } from "node:path";

export interface PythonDependencyFinding {
  packageName: string;
  version: string;
  vulnerabilityId: string;
  fixVersions: string[];
  description: string;
}

export class PipAuditNotAvailableError extends Error {
  constructor() {
    super(
      "pip-audit isn't installed, so Python dependency scanning is unavailable for this project. Install it with 'pip install pip-audit' and re-run — secrets and hygiene checks are unaffected.",
    );
    this.name = "PipAuditNotAvailableError";
  }
}

interface PipAuditRawEntry {
  name: string;
  version: string;
  vulns: Array<{
    id: string;
    fix_versions: string[];
    description: string;
  }>;
}

interface PipAuditRawReport {
  dependencies: PipAuditRawEntry[];
}

/**
 * pip-audit can be invoked directly (if on PATH) or via `python3 -m
 * pip_audit` / `python -m pip_audit` (more portable — works whenever the
 * package is pip-installed regardless of PATH setup, especially common
 * on Windows). Tries each in order, returns null if none work.
 */
async function findPipAuditInvocation(): Promise<string[] | null> {
  const candidates = [["pip-audit"], ["python3", "-m", "pip_audit"], ["python", "-m", "pip_audit"]];

  for (const candidate of candidates) {
    const [cmd, ...args] = candidate;
    const check = await execa(cmd, [...args, "--version"], { reject: false }).catch(() => null);
    if (check?.exitCode === 0) return candidate;
  }

  return null;
}

/**
 * Only requirements.txt is supported for now — pip-audit's pyproject.toml
 * support requires resolving against an actual environment/lockfile,
 * which is a meaningfully different (and heavier) integration than the
 * requirements.txt case. Documented as a known gap rather than attempted
 * partially and silently missing edge cases.
 */
export async function runPythonAuditScan(
  projectRoot: string,
): Promise<PythonDependencyFinding[]> {
  const requirementsPath = join(projectRoot, "requirements.txt");
  if (!existsSync(requirementsPath)) return [];

  const invocation = await findPipAuditInvocation();
  if (!invocation) {
    throw new PipAuditNotAvailableError();
  }

  const [cmd, ...baseArgs] = invocation;
  const result = await execa(
    cmd,
    [...baseArgs, "-r", requirementsPath, "--format", "json", "--progress-spinner", "off"],
    { reject: false },
  );

  // pip-audit exits non-zero both when vulnerabilities are found AND on a
  // genuine internal failure — distinguish by whether stdout is valid
  // JSON, same pattern as the bearer scan-failure fix.
  let parsed: PipAuditRawReport;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error(
      `pip-audit did not produce a valid report: ${result.stderr || result.stdout || "no output"}`,
    );
  }

  const findings: PythonDependencyFinding[] = [];
  for (const dep of parsed.dependencies ?? []) {
    for (const vuln of dep.vulns ?? []) {
      findings.push({
        packageName: dep.name,
        version: dep.version,
        vulnerabilityId: vuln.id,
        fixVersions: vuln.fix_versions,
        description: vuln.description.split("\n")[0].slice(0, 200),
      });
    }
  }

  return findings;
}
