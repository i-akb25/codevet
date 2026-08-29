// Runs automatically after `npm install`. Downloads the gitleaks binary that
// matches the machine actually running the install — this is what makes
// CodeVet work on any real user's laptop, not just the one platform it was
// built on. Same pattern used by esbuild, playwright, and similar tools.

import { mkdir, chmod, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const VENDOR_DIR = join(__dirname, "..", "bin", "vendor");
const GITLEAKS_VERSION = "8.30.1";
const BEARER_VERSION = "2.1.0";

function resolveAssetName() {
  const platform = process.platform; // 'linux' | 'darwin' | 'win32'
  const arch = process.arch; // 'x64' | 'arm64'

  const platformMap = { linux: "linux", darwin: "darwin", win32: "windows" };
  const archMap = { x64: "x64", arm64: "arm64" };

  const mappedPlatform = platformMap[platform];
  const mappedArch = archMap[arch];

  if (!mappedPlatform || !mappedArch) {
    throw new Error(
      `Unsupported platform/arch: ${platform}/${arch}. CodeVet's secret scanner needs a matching gitleaks binary — please open an issue.`,
    );
  }

  const ext = mappedPlatform === "windows" ? "zip" : "tar.gz";
  const binName = mappedPlatform === "windows" ? "gitleaks.exe" : "gitleaks";
  const assetName = `gitleaks_${GITLEAKS_VERSION}_${mappedPlatform}_${mappedArch}.${ext}`;

  return { assetName, ext, binName };
}

async function downloadAndExtract({ url, ext, binName, targetBin, toolName }) {
  if (existsSync(targetBin)) {
    console.log(`[codevet] ${toolName} binary already present, skipping download.`);
    return;
  }

  console.log(`[codevet] downloading ${toolName} for ${process.platform}/${process.arch}...`);

  await mkdir(VENDOR_DIR, { recursive: true });
  const archivePath = join(VENDOR_DIR, `${toolName}-download.${ext}`);

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(
      `Failed to download ${toolName} from ${url} (status ${res.status}). Try re-running 'npm install'.`,
    );
  }
  const buf = Buffer.from(await res.arrayBuffer());
  await import("node:fs/promises").then((fs) => fs.writeFile(archivePath, buf));

  if (ext === "tar.gz") {
    await execFileAsync("tar", ["-xzf", archivePath, "-C", VENDOR_DIR, binName]);
  } else {
    await execFileAsync("powershell", [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `Expand-Archive -LiteralPath '${archivePath}' -DestinationPath '${VENDOR_DIR}' -Force`,
    ]);
  }

  await rm(archivePath);
  await chmod(targetBin, 0o755);

  console.log(`[codevet] ${toolName} installed at ${targetBin}`);
}

async function installGitleaks() {
  const { assetName, ext, binName } = resolveAssetName();
  const url = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${assetName}`;
  const targetBin = join(VENDOR_DIR, process.platform === "win32" ? "gitleaks.exe" : "gitleaks");
  await downloadAndExtract({ url, ext, binName, targetBin, toolName: "gitleaks" });
}

async function installBearer() {
  // Bearer has no native Windows build (confirmed against the project's
  // own release assets and documentation) — skip cleanly with a clear
  // message rather than fail the whole install or produce a confusing
  // crash later when the data-flow scan actually runs.
  if (process.platform === "win32") {
    console.log(
      "[codevet] bearer has no native Windows build — the personal-data-flow check will be unavailable on this machine. Everything else (secrets, dependencies, hygiene) still works normally. WSL is a workaround if you need this specific check.",
    );
    return;
  }

  const platformMap = { linux: "linux", darwin: "darwin" };
  const archMap = { x64: "amd64", arm64: "arm64" };
  const mappedPlatform = platformMap[process.platform];
  const mappedArch = archMap[process.arch];

  if (!mappedPlatform || !mappedArch) {
    console.log(
      `[codevet] bearer has no build for ${process.platform}/${process.arch} — the personal-data-flow check will be unavailable. Everything else still works normally.`,
    );
    return;
  }

  const assetName = `bearer_${BEARER_VERSION}_${mappedPlatform}_${mappedArch}.tar.gz`;
  const url = `https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/${assetName}`;
  const targetBin = join(VENDOR_DIR, "bearer");
  await downloadAndExtract({ url, ext: "tar.gz", binName: "bearer", targetBin, toolName: "bearer" });
}

async function main() {
  await installGitleaks();
  await installBearer();
}

main().catch((err) => {
  console.error(`[codevet] postinstall failed: ${err.message}`);
  console.error(
    `[codevet] you can also install gitleaks manually and place the binary at bin/vendor/${process.platform === "win32" ? "gitleaks.exe" : "gitleaks"} — see https://github.com/gitleaks/gitleaks#installing`,
  );
  // Exit 0 rather than failing the whole `npm install` — a missing scanner
  // binary shouldn't block someone from installing the package at all;
  // the CLI itself checks for the binary and gives a clear error at scan
  // time if it's still missing.
  process.exit(0);
});
