import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";

export interface CodevetConfig {
  secrets: boolean;
  dependencies: boolean;
  hygiene: boolean;
  dataFlow: boolean;
}

const DEFAULT_CONFIG: CodevetConfig = { secrets: true, dependencies: true, hygiene: true, dataFlow: true };

function configPath(projectRoot: string): string {
  return join(projectRoot, ".codevet", "config.json");
}

/**
 * Loads per-project scanner toggles. IMPORTANT: only call this for a
 * project the user actually owns/controls locally. Never call it on a
 * freshly-cloned, not-yet-reviewed target — a malicious repo could ship
 * its own .codevet/config.json set to "disabled" and bypass every check
 * just by being cloned. Untrusted-clone scans always use the full default
 * config, ignoring whatever the repo itself contains.
 */
export async function loadConfig(projectRoot: string): Promise<CodevetConfig> {
  const path = configPath(projectRoot);
  if (!existsSync(path)) return { ...DEFAULT_CONFIG };
  try {
    const raw = await readFile(path, "utf-8");
    return { ...DEFAULT_CONFIG, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export async function saveConfig(
  projectRoot: string,
  config: CodevetConfig,
): Promise<void> {
  const dir = join(projectRoot, ".codevet");
  await mkdir(dir, { recursive: true });
  await writeFile(configPath(projectRoot), JSON.stringify(config, null, 2));
  await ensureGitignored(projectRoot);
}

async function ensureGitignored(projectRoot: string): Promise<void> {
  const gitignorePath = join(projectRoot, ".gitignore");
  const existing = existsSync(gitignorePath)
    ? await readFile(gitignorePath, "utf-8")
    : "";

  if (existing.split("\n").some((line) => line.trim() === ".codevet/")) {
    return;
  }

  const separator = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  await writeFile(gitignorePath, existing + separator + ".codevet/\n");
}
