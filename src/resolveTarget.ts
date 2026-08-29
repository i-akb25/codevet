import { execa } from "execa";
import { mkdtemp, rm, rename, cp, mkdir, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, basename, resolve } from "node:path";

export interface ResolvedTarget {
  path: string;
  /** Set when the target was cloned from a URL — caller decides whether to
   *  keep it (via persistTarget) or discard it (via cleanupTarget). */
  cleanupDir?: string;
  /** True for anything freshly cloned from a URL — the code hasn't been
   *  reviewed by the user yet, so config toggles from inside it must never
   *  be trusted (see config.ts). */
  isUntrustedClone: boolean;
  /** True if the raw args looked like an unquoted, space-containing path that got split by the shell. */
  rejoinedFromSplitArgs: boolean;
  /** Present only for cloned targets — used to name the persisted folder. */
  sourceUrl?: string;
}

const URL_PATTERN = /^(https?:\/\/|git@|git:\/\/|file:\/\/)/i;

/**
 * Commander hands us `args` as whatever positional tokens the shell passed
 * through. If someone runs `codevet scan D:\Some Folder\project` without
 * quotes, PowerShell/cmd/bash all split that into 3 separate tokens before
 * our program ever sees it — confirmed in real testing on Windows. We can't
 * recover the original spacing with certainty, but rejoining with a single
 * space is correct for the overwhelmingly common case (a real folder name
 * with spaces) and far more useful than just erroring.
 */
export async function resolveTarget(
  args: string[],
  cwd: string,
): Promise<ResolvedTarget> {
  const rejoinedFromSplitArgs = args.length > 1;
  const raw = args.length === 0 ? "." : args.join(" ");

  if (URL_PATTERN.test(raw)) {
    const dir = await mkdtemp(join(tmpdir(), "codevet-clone-"));
    await execa("git", ["clone", "--depth", "1", raw, dir]);
    return {
      path: dir,
      cleanupDir: dir,
      isUntrustedClone: true,
      rejoinedFromSplitArgs: false,
      sourceUrl: raw,
    };
  }

  const path = raw === "." ? cwd : raw;
  return { path, isUntrustedClone: false, rejoinedFromSplitArgs };
}

export async function cleanupTarget(target: ResolvedTarget): Promise<void> {
  if (target.cleanupDir) {
    await rm(target.cleanupDir, { recursive: true, force: true }).catch(() => {});
  }
}

function deriveRepoName(url: string): string {
  const cleaned = url.replace(/\.git$/, "").replace(/\/+$/, "");
  const name = basename(cleaned) || "codevet-clone";
  return name.replace(/[^a-zA-Z0-9._-]/g, "-");
}

/**
 * Moves a cloned target from its temp directory to a permanent destination
 * next to where the user ran the command. Only call this after the user
 * has actually agreed to keep it (or the scan came back clean).
 */
export async function persistTarget(
  target: ResolvedTarget,
  destinationParent: string,
): Promise<string> {
  if (!target.cleanupDir || !target.sourceUrl) {
    throw new Error("persistTarget called on a target that wasn't cloned from a URL");
  }

  let destination = join(destinationParent, deriveRepoName(target.sourceUrl));
  let suffix = 2;
  while (existsSync(destination)) {
    destination = join(destinationParent, `${deriveRepoName(target.sourceUrl)}-${suffix}`);
    suffix += 1;
  }

  await moveAcrossDevices(target.cleanupDir, destination);
  await writeProvenanceMarker(destination, target.sourceUrl);
  return destination;
}

interface ProvenanceMarker {
  sourceUrl: string;
  clonedAt: string;
}

function markerPath(dir: string): string {
  return join(dir, ".codevet", "clone-origin.json");
}

async function writeProvenanceMarker(dir: string, sourceUrl: string): Promise<void> {
  const marker: ProvenanceMarker = { sourceUrl, clonedAt: new Date().toISOString() };
  await mkdir(join(dir, ".codevet"), { recursive: true });
  await writeFile(markerPath(dir), JSON.stringify(marker, null, 2));
}

/**
 * Checks whether a folder was actually persisted by `codevet scan <url>`,
 * so the `clean` command can refuse (or clearly warn) before deleting
 * something it didn't create — instead of just trusting any path a user
 * happens to type.
 */
export async function readProvenanceMarker(
  dir: string,
): Promise<ProvenanceMarker | null> {
  try {
    const raw = await readFile(markerPath(dir), "utf-8");
    return JSON.parse(raw) as ProvenanceMarker;
  } catch {
    return null;
  }
}

/**
 * Deletes a folder, but only ever a folder actually inside/under the
 * current working directory tree or an absolute path the user explicitly
 * gave — this is a thin, explicit wrapper so `clean` never silently
 * resolves to something unexpected like the filesystem root.
 */
export async function removeFolder(targetPath: string): Promise<void> {
  const resolved = resolve(targetPath);
  if (resolved === resolve("/") || resolved === resolve(process.env.HOME ?? "/")) {
    throw new Error(`Refusing to remove ${resolved} — this looks like a root or home directory, not a scanned clone.`);
  }
  await rm(resolved, { recursive: true, force: true });
}

/**
 * fs.rename is fast (just a filesystem pointer update) but fails with
 * EXDEV when source and destination are on different drives/filesystems —
 * e.g. a Windows temp folder on C:\ being moved to a project on E:\.
 * Confirmed with a real cross-filesystem mount in testing, matching a
 * real user's exact error. Falls back to copy-then-delete, which works
 * across any boundary at the cost of being slower for large repos.
 */
async function moveAcrossDevices(source: string, destination: string): Promise<void> {
  try {
    await rename(source, destination);
  } catch (err) {
    if (err instanceof Error && "code" in err && err.code === "EXDEV") {
      await cp(source, destination, { recursive: true });
      await rm(source, { recursive: true, force: true });
    } else {
      throw err;
    }
  }
}
