import { existsSync } from "node:fs";
import { mkdir, chmod, rm, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
// This file lives at dist/scanners/ensureBinary.js at runtime — two levels
// up is the package root, matching every other scanner's path resolution.
const PACKAGE_ROOT = join(__dirname, "..", "..");
const VENDOR_DIR = join(PACKAGE_ROOT, "bin", "vendor");

const GITLEAKS_VERSION = "8.30.1";
const BEARER_VERSION = "2.1.0";

interface DownloadSpec {
  toolName: string;
  targetBin: string;
  url: string;
  ext: "tar.gz" | "zip";
  binName: string;
}

function resolveGitleaksSpec(): DownloadSpec | null {
  const platformMap: Record<string, string> = { linux: "linux", darwin: "darwin", win32: "windows" };
  const archMap: Record<string, string> = { x64: "x64", arm64: "arm64" };
  const mappedPlatform = platformMap[process.platform];
  const mappedArch = archMap[process.arch];
  if (!mappedPlatform || !mappedArch) return null;
  const ext = mappedPlatform === "windows" ? "zip" : "tar.gz";
  const binName = mappedPlatform === "windows" ? "gitleaks.exe" : "gitleaks";
  const assetName = `gitleaks_${GITLEAKS_VERSION}_${mappedPlatform}_${mappedArch}.${ext}`;
  return {
    toolName: "gitleaks",
    targetBin: join(VENDOR_DIR, binName),
    url: `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${assetName}`,
    ext,
    binName,
  };
}

function resolveBearerSpec(): DownloadSpec | null {
  if (process.platform === "win32") return null; // confirmed: no native Windows build exists
  const platformMap: Record<string, string> = { linux: "linux", darwin: "darwin" };
  const archMap: Record<string, string> = { x64: "amd64", arm64: "arm64" };
  const mappedPlatform = platformMap[process.platform];
  const mappedArch = archMap[process.arch];
  if (!mappedPlatform || !mappedArch) return null;
  const assetName = `bearer_${BEARER_VERSION}_${mappedPlatform}_${mappedArch}.tar.gz`;
  return {
    toolName: "bearer",
    targetBin: join(VENDOR_DIR, "bearer"),
    url: `https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/${assetName}`,
    ext: "tar.gz",
    binName: "bearer",
  };
}

async function downloadAndExtract(spec: DownloadSpec): Promise<void> {
  await mkdir(VENDOR_DIR, { recursive: true });
  const archivePath = join(VENDOR_DIR, `${spec.toolName}-download.${spec.ext}`);

  const res = await fetch(spec.url);
  if (!res.ok) {
    throw new Error(`Failed to download ${spec.toolName} from ${spec.url} (status ${res.status})`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  await writeFile(archivePath, buf);

  if (spec.ext === "tar.gz") {
    await execFileAsync("tar", ["-xzf", archivePath, "-C", VENDOR_DIR, spec.binName]);
  } else {
    // Windows has no default 'unzip' — PowerShell's Expand-Archive ships
    // with every Windows 10+ machine, same fix as the original postinstall bug.
    await execFileAsync("powershell", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${VENDOR_DIR}' -Force`,
    ]);
  }

  await rm(archivePath);
  await chmod(spec.targetBin, 0o755);
}

/**
 * Ensures a scanner binary is present, downloading it if missing. This is
 * the RUNTIME fallback that makes CodeVet resilient to a real, confirmed
 * issue: npm now blocks postinstall scripts by default (its own
 * "allowScripts" feature) unless a package is explicitly approved.
 * postinstall.mjs's download logic was completely correct — it just
 * never got permission to run on a real user's machine, silently leaving
 * gitleaks missing with no indication why.
 *
 * Rather than depending only on install-time postinstall (a single point
 * of failure), every scanner now self-heals: if its binary isn't there
 * when actually needed, it downloads right then — the user sees exactly
 * what's happening (one-time message) instead of a permanent, confusing
 * failure that "try npm install again" can never actually fix.
 */
export async function ensureBinary(tool: "gitleaks" | "bearer"): Promise<string | null> {
  const spec = tool === "gitleaks" ? resolveGitleaksSpec() : resolveBearerSpec();
  if (!spec) return null; // unsupported platform (e.g. bearer on Windows) — not an error

  if (existsSync(spec.targetBin)) {
    return spec.targetBin;
  }

  console.error(
    `[codevet] ${spec.toolName} binary not found — this usually means npm blocked the install script (npm's "allowScripts" security feature). Downloading it directly now instead — this only happens once.`,
  );
  await downloadAndExtract(spec);
  return spec.targetBin;
}
