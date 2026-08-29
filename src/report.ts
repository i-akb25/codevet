import chalk from "chalk";
import type { SecretFinding } from "./scanners/gitleaksScanner.js";
import type { DependencyFinding } from "./scanners/npmAuditScanner.js";
import type { HygieneFinding } from "./scanners/hygieneScanner.js";
import type { DataFlowFinding } from "./scanners/bearerScanner.js";
import type { PythonDependencyFinding } from "./scanners/pipAuditScanner.js";

/**
 * One consistent High/Moderate/Low(/Critical) label used everywhere in the
 * report — this is the direct signal for "what do I actually need to fix
 * before shipping" vs "what can wait." Critical/High mean real,
 * meaningfully exploitable risk; Moderate is real but rarely the sole
 * cause of an incident on its own; Low is worth doing but not urgent.
 */
export function hygieneSeverityLabel(severity: HygieneFinding["severity"]): string {
  switch (severity) {
    case "critical":
      return chalk.bgRed.white.bold(" CRITICAL ");
    case "high":
      return chalk.red.bold("✖ HIGH");
    case "moderate":
      return chalk.yellow.bold("○ MODERATE");
    case "low":
      return chalk.dim("○ LOW");
  }
}

export interface ScanReport {
  secrets: SecretFinding[];
  dependencies: DependencyFinding[];
  hygiene: HygieneFinding[];
  dataFlow: DataFlowFinding[];
  pythonDependencies: PythonDependencyFinding[];
  pythonDependenciesApplicable?: boolean;
  pythonDependenciesFailed?: boolean;
  pythonDependenciesUnavailableReason?: string;
  secretsScanSkipped?: boolean;
  dependenciesScanSkipped?: boolean;
  dependenciesScanFailed?: boolean;
  dependenciesUnavailableReason?: string;
  dataFlowScanSkipped?: boolean;
  dataFlowScanFailed?: boolean;
  dataFlowUnavailableReason?: string;
}

export function hasFindings(report: ScanReport): boolean {
  return (
    report.secrets.length > 0 ||
    report.dependencies.length > 0 ||
    report.hygiene.length > 0 ||
    report.dataFlow.length > 0 ||
    report.pythonDependencies.length > 0 ||
    Boolean(report.dataFlowScanFailed) ||
    Boolean(report.dependenciesScanFailed) ||
    Boolean(report.pythonDependenciesFailed)
  );
}

export function hasHighRiskFindings(report: ScanReport): boolean {
  const hasCriticalOrHighDep = report.dependencies.some(
    (d) => d.severity === "critical" || d.severity === "high",
  );
  const hasCriticalOrHighDataFlow = report.dataFlow.some(
    (d) => d.severity === "critical" || d.severity === "high",
  );
  const hasCriticalOrHighHygiene = report.hygiene.some(
    (h) => h.severity === "critical" || h.severity === "high",
  );
  // A scan that was attempted but genuinely failed (e.g. bearer's rule
  // download hit a rate limit) must never be treated as equivalent to a
  // clean result — confirmed as a real risk in testing, where forcing a
  // success exit code masked exactly this failure mode.
  //
  // pythonDependencies is deliberately NOT included here — pip-audit's
  // JSON output has no severity field at all (confirmed in testing,
  // unlike npm audit which does), so treating every Python CVE as
  // high-risk would fabricate a confidence level we don't actually have.
  // These findings are still always shown in the report, just not used
  // to gate CI.
  return (
    report.secrets.length > 0 ||
    hasCriticalOrHighDep ||
    hasCriticalOrHighDataFlow ||
    hasCriticalOrHighHygiene ||
    Boolean(report.dataFlowScanFailed) ||
    Boolean(report.dependenciesScanFailed) ||
    Boolean(report.pythonDependenciesFailed)
  );
}

export function printReport(report: ScanReport): void {
  if (report.secretsScanSkipped) {
    console.log(chalk.dim("○ Secret scan skipped."));
  } else if (report.secrets.length === 0) {
    console.log(chalk.green("✔ No exposed secrets found."));
  } else {
    console.log(chalk.red(`✖ ${report.secrets.length} exposed secret(s) found:\n`));
    for (const s of report.secrets) {
      console.log(chalk.bold(`  ${s.file}:${s.line}`));
      console.log(`  ${s.description}`);
      console.log(
        chalk.dim(
          "  Why it matters: this file is likely tracked by git — anyone with repo access (or anyone who forks a public repo) can read this credential directly.\n",
        ),
      );
    }
  }

  console.log(chalk.dim("\nChecking dependencies for known vulnerabilities...\n"));

  if (report.dependenciesScanFailed) {
    console.log(chalk.red(`⚠ Dependency scan FAILED — this is not a clean result: ${report.dependenciesUnavailableReason}`));
  } else if (report.dependenciesScanSkipped) {
    console.log(
      chalk.dim(
        report.dependenciesUnavailableReason
          ? `○ Dependency scan skipped — ${report.dependenciesUnavailableReason}`
          : "○ Dependency scan skipped.",
      ),
    );
  } else if (report.dependencies.length === 0) {
    console.log(chalk.green("✔ No known-vulnerable dependencies found."));
  } else {
    console.log(
      chalk.red(`✖ ${report.dependencies.length} package(s) with known vulnerabilities:\n`),
    );
    for (const d of report.dependencies) {
      const severityColor =
        d.severity === "critical" || d.severity === "high" ? chalk.red : chalk.yellow;
      console.log(
        severityColor.bold(`  ${d.packageName} — ${d.severity.toUpperCase()}`) +
          chalk.dim(d.isDirect ? "" : " (transitive dependency)"),
      );
      console.log(`  ${d.advisories[0].title}`);
      if (d.advisories.length > 1) {
        console.log(chalk.dim(`  + ${d.advisories.length - 1} more advisor${d.advisories.length - 1 === 1 ? "y" : "ies"} for this package`));
      }
      console.log(
        chalk.dim(
          `  Fix: ${d.fixAvailable ? d.fixAvailable : "no automatic fix published yet — check the advisory"}\n`,
        ),
      );
    }
  }

  if (report.pythonDependenciesApplicable) {
    console.log(chalk.dim("\nChecking Python dependencies for known vulnerabilities (via pip-audit)...\n"));

    if (report.pythonDependenciesFailed) {
      console.log(chalk.red(`⚠ Python dependency scan FAILED — this is not a clean result: ${report.pythonDependenciesUnavailableReason}`));
    } else if (report.pythonDependenciesUnavailableReason) {
      console.log(chalk.dim(`○ ${report.pythonDependenciesUnavailableReason}`));
    } else if (report.pythonDependencies.length === 0) {
      console.log(chalk.green("✔ No known-vulnerable Python dependencies found."));
    } else {
      console.log(
        chalk.yellow(
          `○ ${report.pythonDependencies.length} package(s) with known CVEs — pip-audit does not provide severity ratings, so these are listed unranked. Prioritize by whether a fix version exists:\n`,
        ),
      );
      for (const p of report.pythonDependencies) {
        console.log(chalk.bold(`  ${p.packageName}@${p.installedVersion}`));
        for (const advisory of p.advisories) {
          console.log(`    ${advisory.id}: ${advisory.description}`);
          console.log(
            chalk.dim(
              `    Fix: ${advisory.fixVersions.length > 0 ? `upgrade to ${advisory.fixVersions[advisory.fixVersions.length - 1]}` : "no fix published yet — check the advisory"}`,
            ),
          );
        }
        console.log("");
      }
    }
  }

  console.log(chalk.dim("\nChecking for missing security middleware...\n"));

  if (report.hygiene.length === 0) {
    console.log(chalk.green("✔ No missing middleware patterns detected."));
  } else {
    for (const h of report.hygiene) {
      const label = hygieneSeverityLabel(h.severity);
      console.log(`${label} ${chalk.bold(h.title)}`);
      console.log(`  ${h.description}`);
      if (h.verifyNote) {
        console.log(chalk.dim(`  Verify: ${h.verifyNote}`));
      }
      console.log(chalk.dim(`  Suggested fix — ${h.fix.title}:`));
      console.log(chalk.dim(h.fix.code.split("\n").map((l) => "    " + l).join("\n")));
      console.log("");
    }
  }

  console.log(chalk.dim("\nChecking personal data flow (via bearer)...\n"));

  if (report.dataFlowScanFailed) {
    console.log(chalk.red(`⚠ Data flow scan FAILED — this is not a clean result: ${report.dataFlowUnavailableReason}`));
  } else if (report.dataFlowScanSkipped) {
    console.log(
      chalk.dim(
        report.dataFlowUnavailableReason
          ? `○ Data flow scan skipped — ${report.dataFlowUnavailableReason}`
          : "○ Data flow scan skipped.",
      ),
    );
  } else if (report.dataFlow.length === 0) {
    console.log(chalk.green("✔ No personal-data-flow risks found."));
  } else {
    console.log(chalk.red(`✖ ${report.dataFlow.length} data-flow finding(s):\n`));
    for (const d of report.dataFlow) {
      const severityColor = d.severity === "critical" || d.severity === "high" ? chalk.red : chalk.yellow;
      console.log(severityColor.bold(`  ${d.title} — ${d.severity.toUpperCase()}`));
      console.log(`  ${d.file}:${d.line}`);
      console.log(chalk.dim(`  ${d.description}\n`));
    }
  }
}
