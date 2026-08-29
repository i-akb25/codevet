import { execa } from "execa";
import { readFile, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = join(__dirname, "..", "..");
const BEARER_BIN = join(
  PACKAGE_ROOT,
  "bin",
  "vendor",
  process.platform === "win32" ? "bearer.exe" : "bearer",
);

export interface DataFlowFinding {
  ruleId: string;
  title: string;
  description: string;
  file: string;
  line: number;
  severity: "critical" | "high" | "medium" | "low";
}

export class BearerBinaryMissingError extends Error {
  constructor() {
    const isWindows = process.platform === "win32";
    super(
      isWindows
        ? "bearer has no native Windows build, so the personal-data-flow check isn't available on this machine — secrets, dependencies, and hygiene checks are unaffected. WSL is a workaround if you need this specific check."
        : `bearer binary not found at ${BEARER_BIN}. This usually means the postinstall step didn't run — try 'npm install' again inside the codevet package.`,
    );
    this.name = "BearerBinaryMissingError";
  }
}

export class BearerScanFailedError extends Error {
  constructor(reason: string) {
    super(
      `bearer's data-flow scan did not actually run: ${reason}. This is being reported as a failure rather than "no findings" — a scan that never ran is not the same as a clean result.`,
    );
    this.name = "BearerScanFailedError";
  }
}

// Bearer's default security-report ruleset includes general Express
// hygiene rules that CodeVet's own hygiene scanner already covers
// (helmet, server fingerprinting) — excluded here to avoid showing the
// same finding twice from two different scanners. Everything else stays,
// since Bearer's actual differentiator is data-flow rules like
// "javascript_lang_logger" (PII logged) that no pattern-based scanner
// (including CodeVet's own hygiene checks) can detect — those require
// understanding where a value came from and where it goes, not just
// whether a line matches a regex.
const OVERLAPS_WITH_HYGIENE_SCANNER = new Set([
  "javascript_express_helmet_missing",
  "javascript_express_reduce_fingerprint",
]);

interface BearerRawFinding {
  id: string;
  title: string;
  description: string;
  full_filename: string;
  filename: string;
  line_number: number;
}

type BearerRawReport = Record<string, BearerRawFinding[]>; // keyed by severity

export async function runBearerScan(projectRoot: string): Promise<DataFlowFinding[]> {
  if (!existsSync(BEARER_BIN)) {
    throw new BearerBinaryMissingError();
  }

  const reportPath = join(projectRoot, ".codevet-bearer-report.json");

  try {
    // IMPORTANT: do NOT pass --exit-code 0 here. That flag forces bearer
    // to always report success, which was confirmed in testing to mask a
    // genuine internal failure (rule definitions failing to download,
    // producing "0 rules found") as a silent, false "no findings" result
    // — exactly the kind of fake-clean result this project exists to
    // prevent. We handle bearer's real non-zero exit code ourselves below
    // instead of suppressing it.
    const result = await execa(
      BEARER_BIN,
      [
        "scan",
        projectRoot,
        "--format",
        "json",
        "--output",
        reportPath,
        "--quiet",
        "--hide-progress-bar",
        "--no-rule-meta",
        // Directories holding example/template code (e.g. CodeVet's own
        // fix-library, or any project keeping similar reference snippets)
        // are structurally full of intentional secret-handling examples —
        // Bearer's static analysis can't distinguish a variable named
        // `SECRET` read correctly from process.env inside a documentation
        // string from a real hardcoded secret in executable code.
        // Confirmed as a real false-positive source by testing against
        // CodeVet's own repo before shipping this default.
        "--skip-path",
        "**/fix-library/**,**/fixLibrary/**,**/security-templates/**",
      ],
      { reject: false },
    );

    // Bearer's own internal errors (e.g. rule definitions failing to
    // download) print "Error: ..." to stderr and produce an empty/invalid
    // report, distinct from its normal "exit non-zero because findings
    // exist" behavior. Confirmed this distinction by directly reproducing
    // a rule-download failure (GitHub API rate limit) in testing.
    const stderrText = result.stderr ?? "";
    const errorLine = stderrText.split("\n").find((line) => line.includes("Error:"));
    if (errorLine) {
      throw new BearerScanFailedError(errorLine.trim());
    }

    const raw = await readFile(reportPath, "utf-8").catch(() => null);
    if (raw === null) {
      throw new BearerScanFailedError("no report file was produced");
    }

    const parsed = JSON.parse(raw) as BearerRawReport;

    const findings: DataFlowFinding[] = [];
    for (const [severity, entries] of Object.entries(parsed)) {
      if (!["critical", "high", "medium", "low"].includes(severity)) continue;
      for (const entry of entries) {
        if (OVERLAPS_WITH_HYGIENE_SCANNER.has(entry.id)) continue;
        findings.push({
          ruleId: entry.id,
          title: entry.title,
          description: entry.description.split("\n")[0].replace(/^##\s*Description\s*/, "").trim() || entry.title,
          file: entry.filename,
          line: entry.line_number,
          severity: severity as DataFlowFinding["severity"],
        });
      }
    }

    return findings;
  } finally {
    await unlink(reportPath).catch(() => {});
  }
}
