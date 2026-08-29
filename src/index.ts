#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { resolve, join } from "node:path";
import { existsSync } from "node:fs";
import { detectStack } from "./detectors/detectStack.js";
import { runGitleaksScan, GitleaksBinaryMissingError } from "./scanners/gitleaksScanner.js";
import { runNpmAuditScan, NpmAuditScanFailedError } from "./scanners/npmAuditScanner.js";
import { runHygieneScan } from "./scanners/hygieneScanner.js";
import { runBearerScan, BearerBinaryMissingError, BearerScanFailedError } from "./scanners/bearerScanner.js";
import { runPipAuditScan, PipAuditNotInstalledError, PipAuditScanFailedError } from "./scanners/pipAuditScanner.js";
import { resolveTarget, cleanupTarget, persistTarget, readProvenanceMarker, removeFolder } from "./resolveTarget.js";
import { loadConfig, saveConfig, type CodevetConfig } from "./config.js";
import { promptConfirm } from "./promptConfirm.js";
import { printReport, hasFindings, hasHighRiskFindings, type ScanReport } from "./report.js";
import { runFix, removeDependency } from "./scanners/npmFixActions.js";

const program = new Command();

program
  .name("codevet")
  .description("Vet your code before it ships — free, open-source security scanning")
  .version("0.0.1");

program
  .command("scan")
  .description(
    "Scan a project for security issues. Defaults to the current directory. Accepts a local path or a git/GitHub URL (which gets shallow-cloned to a temp folder first, so you can review it before deciding to keep it).",
  )
  .argument(
    "[path...]",
    "project path or git URL to scan (defaults to the current directory)",
  )
  .option("--no-secrets", "skip the secret-scanning check for this run only")
  .option("--no-dependencies", "skip the dependency-vulnerability check for this run only")
  .option("--no-hygiene", "skip the missing-middleware check for this run only")
  .option("--no-data-flow", "skip the personal-data-flow check for this run only")
  .option("--json <path>", "also write a machine-readable JSON report to this path (for CI/tooling)")
  .option("--fail-on-high-risk", "exit with a non-zero code if any secret or high/critical dependency finding is present")
  .action(async (pathArgs: string[], options: { secrets: boolean; dependencies: boolean; hygiene: boolean; dataFlow: boolean; json?: string; failOnHighRisk?: boolean }) => {
    const target = await resolveTarget(pathArgs, process.cwd());

    if (target.rejoinedFromSplitArgs) {
      console.log(
        chalk.yellow(
          `Note: your path contains spaces and wasn't quoted, so I rejoined it as: "${target.path}". If that's wrong, wrap the path in quotes.`,
        ),
      );
    }

    try {
      // A path that doesn't exist must be a hard error, never a silent
      // "clean" result — confirmed as a real risk: gitleaks, npm audit,
      // and the hygiene scanner all previously proceeded on a nonexistent
      // path and reported "no findings," which is indistinguishable from
      // a genuine clean scan. Bearer already validates this internally
      // (confirmed it correctly errors on its own); this check makes the
      // other three scanners fail the same safe way.
      if (!existsSync(target.path)) {
        console.log(chalk.red(`✖ ${target.path} does not exist — nothing was scanned.`));
        process.exitCode = 1;
        return;
      }

      console.log(chalk.bold("\nCodeVet — scanning " + target.path + "\n"));

      const stacks = detectStack(target.path);
      if (stacks.length === 0) {
        console.log(
          chalk.yellow(
            "No recognized stack found (looked for package.json, requirements.txt, build.gradle, Podfile).",
          ),
        );
      } else {
        console.log(
          chalk.dim(
            "Detected: " + stacks.map((s) => `${s.stack} (${s.matchedOn})`).join(", "),
          ),
        );
      }

      // Untrusted clones ALWAYS run the full scan, regardless of any
      // .codevet/config.json the repo itself might contain — otherwise a
      // malicious repo could just ship a config that disables every check
      // and sail through review undetected.
      const config: CodevetConfig = target.isUntrustedClone
        ? { secrets: true, dependencies: true, hygiene: true, dataFlow: true }
        : await loadConfig(target.path);

      const runSecrets = options.secrets !== false && config.secrets;
      const runDependencies = options.dependencies !== false && config.dependencies;
      const runHygiene = options.hygiene !== false && config.hygiene;
      const runDataFlow = options.dataFlow !== false && config.dataFlow;

      console.log(chalk.dim("\nChecking for exposed secrets...\n"));
      const secrets = runSecrets ? await runGitleaksScan(target.path) : [];

      // Wrapped exactly like the bearer scanner below — confirmed as a
      // real crash risk in testing: npm audit's own lockfile-generation
      // step can fail (e.g. an npm internal error on a specific
      // package.json), and left uncaught this took down the ENTIRE scan
      // command, hiding secrets/hygiene/data-flow results that had
      // nothing to do with the failure. Never let one scanner's failure
      // silence the others.
      let dependencies: Awaited<ReturnType<typeof runNpmAuditScan>> = [];
      let dependenciesUnavailableReason: string | undefined;
      let dependenciesFailed = false;
      if (runDependencies) {
        try {
          dependencies = await runNpmAuditScan(target.path);
        } catch (err) {
          if (err instanceof NpmAuditScanFailedError) {
            dependenciesUnavailableReason = err.message;
            dependenciesFailed = true;
          } else {
            throw err;
          }
        }
      }

      let dataFlow: Awaited<ReturnType<typeof runBearerScan>> = [];
      let dataFlowUnavailableReason: string | undefined;
      let dataFlowFailed = false;
      if (runDataFlow) {
        try {
          dataFlow = await runBearerScan(target.path);
        } catch (err) {
          if (err instanceof BearerBinaryMissingError) {
            dataFlowUnavailableReason = err.message;
          } else if (err instanceof BearerScanFailedError) {
            dataFlowUnavailableReason = err.message;
            dataFlowFailed = true;
          } else {
            throw err;
          }
        }
      }

      // Gated by the same toggle as npm audit — conceptually both are
      // "dependency scanning," just for a different ecosystem, so one
      // config field covers both rather than adding a Python-specific one.
      // Applicability now also covers pyproject.toml, not just
      // requirements.txt — closing a gap explicitly flagged as missing
      // in an earlier, less capable version of this scanner.
      let pythonDependencies: Awaited<ReturnType<typeof runPipAuditScan>> = [];
      let pythonDependenciesUnavailableReason: string | undefined;
      let pythonDependenciesFailed = false;
      const pythonDependenciesApplicable =
        runDependencies &&
        (existsSync(join(target.path, "requirements.txt")) ||
          existsSync(join(target.path, "pyproject.toml")));
      if (pythonDependenciesApplicable) {
        try {
          pythonDependencies = await runPipAuditScan(target.path);
        } catch (err) {
          if (err instanceof PipAuditNotInstalledError) {
            pythonDependenciesUnavailableReason = err.message;
          } else if (err instanceof PipAuditScanFailedError) {
            pythonDependenciesUnavailableReason = err.message;
            pythonDependenciesFailed = true;
          } else {
            throw err;
          }
        }
      }

      let hygiene: Awaited<ReturnType<typeof runHygieneScan>> = [];
      if (runHygiene) {
        hygiene = await runHygieneScan(target.path);
      }

      const report: ScanReport = {
        secrets,
        dependencies,
        hygiene,
        dataFlow,
        pythonDependencies,
        pythonDependenciesApplicable,
        pythonDependenciesFailed,
        pythonDependenciesUnavailableReason,
        secretsScanSkipped: !runSecrets,
        dependenciesScanSkipped: !runDependencies || (Boolean(dependenciesUnavailableReason) && !dependenciesFailed),
        dependenciesScanFailed: dependenciesFailed,
        dependenciesUnavailableReason,
        dataFlowScanSkipped: !runDataFlow || (Boolean(dataFlowUnavailableReason) && !dataFlowFailed),
        dataFlowScanFailed: dataFlowFailed,
        dataFlowUnavailableReason,
      };

      printReport(report);

      if (options.json) {
        const { writeFile } = await import("node:fs/promises");
        await writeFile(options.json, JSON.stringify(report, null, 2));
        console.log(chalk.dim(`\nJSON report written to ${options.json}`));
      }

      if (target.isUntrustedClone) {
        await handleUntrustedCloneDecision(target, report);
      }

      if (options.failOnHighRisk && hasHighRiskFindings(report)) {
        process.exitCode = 1;
      }
    } catch (err) {
      if (err instanceof GitleaksBinaryMissingError) {
        console.log(chalk.red("✖ " + err.message));
      } else {
        throw err;
      }
    } finally {
      if (!target.isUntrustedClone) {
        await cleanupTarget(target);
      }
      // Untrusted-clone cleanup/persistence is handled inside
      // handleUntrustedCloneDecision instead — it decides whether to keep
      // or delete based on the user's answer.
    }
  });

async function handleUntrustedCloneDecision(
  target: Awaited<ReturnType<typeof resolveTarget>>,
  report: ScanReport,
): Promise<void> {
  if (!hasFindings(report)) {
    const destination = await persistTarget(target, process.cwd());
    console.log(chalk.green(`\n✔ No issues found — kept at ${destination}`));
    return;
  }

  const serious = hasHighRiskFindings(report);
  const proceed = await promptConfirm(
    chalk.yellow(
      `\n${serious ? "⚠ Serious issues" : "Some issues"} were found above. Do you still want to keep this repository?`,
    ),
  );

  if (proceed) {
    const destination = await persistTarget(target, process.cwd());
    console.log(
      chalk.yellow(
        `Kept at ${destination} despite the issues above — review them before running this code.`,
      ),
    );
  } else {
    await cleanupTarget(target);
    console.log(chalk.dim("Discarded — nothing was kept."));
  }
}

const configCmd = program
  .command("config")
  .description(
    "Enable or disable specific scanners for this project (stored in .codevet/config.json)",
  );

configCmd
  .command("status")
  .argument("[path]", "project path", ".")
  .action(async (path: string) => {
    const config = await loadConfig(path === "." ? process.cwd() : path);
    console.log(chalk.bold("\nCodeVet scanner status:\n"));
    console.log(
      `  secrets:      ${config.secrets ? chalk.green("enabled") : chalk.red("disabled")}`,
    );
    console.log(
      `  dependencies: ${config.dependencies ? chalk.green("enabled") : chalk.red("disabled")}`,
    );
    console.log(
      `  hygiene:      ${config.hygiene ? chalk.green("enabled") : chalk.red("disabled")}`,
    );
    console.log(
      `  data-flow:    ${config.dataFlow ? chalk.green("enabled") : chalk.red("disabled")}`,
    );
  });

for (const action of ["enable", "disable"] as const) {
  configCmd
    .command(action)
    .argument("<scanner>", "'secrets', 'dependencies', 'hygiene', 'data-flow', or 'all'")
    .argument("[path]", "project path", ".")
    .description(`${action === "enable" ? "Enable" : "Disable"} a scanner for this project`)
    .action(async (scanner: string, path: string) => {
      const projectRoot = path === "." ? process.cwd() : path;
      const config = await loadConfig(projectRoot);
      const value = action === "enable";

      if (scanner === "all") {
        config.secrets = value;
        config.dependencies = value;
        config.hygiene = value;
        config.dataFlow = value;
      } else if (scanner === "data-flow") {
        config.dataFlow = value;
      } else if (scanner === "secrets" || scanner === "dependencies" || scanner === "hygiene") {
        config[scanner] = value;
      } else {
        console.log(
          chalk.red(`Unknown scanner "${scanner}" — expected 'secrets', 'dependencies', 'hygiene', 'data-flow', or 'all'.`),
        );
        return;
      }

      await saveConfig(projectRoot, config);
      console.log(
        chalk.green(`✔ ${scanner} scanner${scanner === "all" ? "s" : ""} ${action}d for this project.`),
      );
    });
}

program
  .command("clean")
  .description("Remove a repository that CodeVet previously cloned and kept")
  .argument("<path>", "path to the folder to remove")
  .option("--yes", "skip the confirmation prompt")
  .action(async (path: string, options: { yes: boolean }) => {
    const target = resolve(path);

    if (!existsSync(target)) {
      console.log(chalk.red(`✖ ${target} doesn't exist.`));
      return;
    }

    const marker = await readProvenanceMarker(target);

    if (marker) {
      console.log(
        chalk.dim(
          `This was cloned from ${marker.sourceUrl} on ${new Date(marker.clonedAt).toLocaleString()}.`,
        ),
      );
    } else {
      console.log(
        chalk.yellow(
          "This folder doesn't have a CodeVet clone marker — it may not have been created by 'codevet scan <url>'. Double-check the path before continuing.",
        ),
      );
    }

    const proceed = options.yes || (await promptConfirm(`Remove ${target}?`));
    if (!proceed) {
      console.log(chalk.dim("Cancelled — nothing was removed."));
      return;
    }

    try {
      await removeFolder(target);
      console.log(chalk.green(`✔ Removed ${target}`));
    } catch (err) {
      console.log(chalk.red("✖ " + (err instanceof Error ? err.message : String(err))));
    }
  });

program
  .command("fix")
  .description(
    "Upgrade flagged dependencies to a safe version (runs 'npm audit fix' — does not change major-version constraints unless --force is passed).",
  )
  .argument("[path]", "project path", ".")
  .option("--force", "allow major-version upgrades that may include breaking changes")
  .action(async (path: string, options: { force: boolean }) => {
    const projectRoot = path === "." ? process.cwd() : path;

    if (options.force) {
      console.log(
        chalk.yellow(
          "⚠ Running with --force: this can upgrade packages across major versions, which may break your code. Review the diff before committing.",
        ),
      );
    }

    console.log(chalk.dim("\nRunning npm audit fix...\n"));
    const result = await runFix(projectRoot, options.force);

    const beforeCount = result.before.length;
    const afterCount = result.after.length;
    const fixedCount = beforeCount - afterCount;

    if (fixedCount > 0) {
      console.log(chalk.green(`✔ Fixed ${fixedCount} of ${beforeCount} flagged package(s).`));
    } else {
      console.log(chalk.yellow("No packages were auto-fixable."));
    }

    if (afterCount > 0) {
      console.log(
        chalk.yellow(
          `${afterCount} package(s) still flagged — these likely need a major-version bump. Run 'codevet fix --force' to attempt those, or 'codevet remove-dependency <name>' if a flagged package isn't actually needed.`,
        ),
      );
      for (const d of result.after) {
        console.log(chalk.dim(`  - ${d.packageName} (${d.severity})`));
      }
    }
  });

program
  .command("remove-dependency")
  .description(
    "Explicitly uninstall a flagged package. WARNING: this is different from 'fix' — if your code actually imports this package, removing it will break your app. Only use this for packages you're sure are unused.",
  )
  .argument("<package>", "the package name to remove")
  .argument("[path]", "project path", ".")
  .option("--yes", "skip the confirmation prompt")
  .action(async (packageName: string, path: string, options: { yes: boolean }) => {
    const projectRoot = path === "." ? process.cwd() : path;

    console.log(
      chalk.yellow(
        `⚠ This will run 'npm uninstall ${packageName}'. If your code imports this package, your app will break until you either restore it or remove those imports.`,
      ),
    );

    const proceed = options.yes || (await promptConfirm(`Remove ${packageName}?`));
    if (!proceed) {
      console.log(chalk.dim("Cancelled — nothing was removed."));
      return;
    }

    const result = await removeDependency(projectRoot, packageName);

    if (!result.wasPresent) {
      console.log(chalk.yellow(`${packageName} wasn't found in package.json — nothing to remove.`));
    } else if (result.removed) {
      console.log(chalk.green(`✔ Removed ${packageName}.`));
    } else {
      console.log(chalk.red(`✖ Failed to remove ${packageName}: ${result.error}`));
    }
  });

program.parse();
