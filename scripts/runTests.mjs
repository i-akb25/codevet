// Runs the test suite by explicitly enumerating *.test.ts files via
// Node's fs module, then passing that explicit file list to `node --test`.
//
// Why this exists: `node --test tests/*.test.ts` relies on the SHELL to
// expand the glob before node ever sees it. bash does this automatically
// (confirmed working in CI on ubuntu/macos), but PowerShell/cmd.exe do
// NOT expand globs for arguments passed to a child process — Windows CI
// failed with "Could not find 'tests/*.test.ts'" because node received
// the literal, unexpanded string. Node's own --test directory-scanning
// was tried as an alternative and confirmed NOT to reliably discover
// .test.ts files under the tsx loader either (found 1 instead of the
// real 17 test cases). Enumerating via fs.readdirSync sidesteps both
// problems — it's just JavaScript, identical behavior on every OS.
import { readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const testsDir = join(__dirname, "..", "tests");

const testFiles = readdirSync(testsDir)
  .filter((f) => f.endsWith(".test.ts"))
  .map((f) => join(testsDir, f));

if (testFiles.length === 0) {
  console.error("[codevet] no *.test.ts files found in tests/ — something is wrong.");
  process.exit(1);
}

const child = spawn(
  process.execPath,
  ["--import", "tsx", "--test", ...testFiles],
  { stdio: "inherit" },
);

child.on("exit", (code) => {
  process.exit(code ?? 1);
});
