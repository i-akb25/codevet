import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectStack } from "../dist/detectors/detectStack.js";

function makeTempProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  for (const [name, content] of Object.entries(files)) {
    writeFileSync(join(dir, name), content);
  }
  return dir;
}

test("detects a Node project via package.json", () => {
  const dir = makeTempProject({ "package.json": "{}" });
  const result = detectStack(dir);
  assert.equal(result.length, 1);
  assert.equal(result[0].stack, "node");
  rmSync(dir, { recursive: true, force: true });
});

test("detects a Python project via requirements.txt", () => {
  const dir = makeTempProject({ "requirements.txt": "flask==3.0.0" });
  const result = detectStack(dir);
  assert.equal(result.length, 1);
  assert.equal(result[0].stack, "python");
  rmSync(dir, { recursive: true, force: true });
});

test("detects multiple stacks in one project", () => {
  const dir = makeTempProject({
    "package.json": "{}",
    "requirements.txt": "",
  });
  const result = detectStack(dir);
  assert.equal(result.length, 2);
  rmSync(dir, { recursive: true, force: true });
});

test("returns empty array for an unrecognized project", () => {
  const dir = makeTempProject({ "readme.txt": "just a text file" });
  const result = detectStack(dir);
  assert.equal(result.length, 0);
  rmSync(dir, { recursive: true, force: true });
});
