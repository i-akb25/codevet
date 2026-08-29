import { execa } from "execa";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { runNpmAuditScan, type DependencyFinding } from "./npmAuditScanner.js";

export interface FixResult {
  before: DependencyFinding[];
  after: DependencyFinding[];
  ranForceFix: boolean;
}

/**
 * Runs `npm audit fix` — upgrades packages to the newest version that
 * satisfies the existing semver range in package.json. This is the "safe"
 * remediation: it does not change your major version constraints unless
 * `force` is explicitly requested, matching npm's own safety model rather
 * than inventing our own.
 */
export async function runFix(
  projectRoot: string,
  force: boolean,
): Promise<FixResult> {
  const before = await runNpmAuditScan(projectRoot);

  const args = ["audit", "fix"];
  if (force) args.push("--force");

  await execa("npm", args, { cwd: projectRoot, reject: false });

  const after = await runNpmAuditScan(projectRoot);

  return { before, after, ranForceFix: force };
}

export interface RemoveDependencyResult {
  packageName: string;
  wasPresent: boolean;
  removed: boolean;
  error?: string;
}

/**
 * Explicitly uninstalls a single flagged package. This is NOT the same as
 * `fix` — removing a dependency the application actually imports and uses
 * will break the app. This exists for the case where a flagged package is
 * unused/leftover and the right move is deleting it outright, not
 * upgrading it. The CLI layer is responsible for warning the user before
 * calling this.
 */
export async function removeDependency(
  projectRoot: string,
  packageName: string,
): Promise<RemoveDependencyResult> {
  const packageJsonPath = join(projectRoot, "package.json");
  if (!existsSync(packageJsonPath)) {
    return { packageName, wasPresent: false, removed: false, error: "No package.json found" };
  }

  const packageJson = JSON.parse(await readFile(packageJsonPath, "utf-8")) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  const wasPresent = Boolean(
    packageJson.dependencies?.[packageName] || packageJson.devDependencies?.[packageName],
  );

  if (!wasPresent) {
    return { packageName, wasPresent: false, removed: false };
  }

  const result = await execa("npm", ["uninstall", packageName], {
    cwd: projectRoot,
    reject: false,
  });

  return {
    packageName,
    wasPresent: true,
    removed: result.exitCode === 0,
    error: result.exitCode !== 0 ? result.stderr : undefined,
  };
}
