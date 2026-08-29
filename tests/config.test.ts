import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, saveConfig } from "../dist/config.js";

test("loadConfig returns all-enabled defaults when no config file exists", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  const config = await loadConfig(dir);
  assert.deepEqual(config, { secrets: true, dependencies: true, hygiene: true, dataFlow: true });
  rmSync(dir, { recursive: true, force: true });
});

test("saveConfig persists and loadConfig reads it back correctly", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  await saveConfig(dir, { secrets: false, dependencies: true, hygiene: false, dataFlow: false });
  const config = await loadConfig(dir);
  assert.deepEqual(config, { secrets: false, dependencies: true, hygiene: false, dataFlow: false });
  rmSync(dir, { recursive: true, force: true });
});

test("saveConfig adds .codevet/ to .gitignore automatically", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  await saveConfig(dir, { secrets: true, dependencies: true, hygiene: true, dataFlow: true });
  const gitignore = readFileSync(join(dir, ".gitignore"), "utf-8");
  assert.match(gitignore, /\.codevet\//);
  rmSync(dir, { recursive: true, force: true });
});

test("saveConfig does not duplicate the .gitignore entry on repeated saves", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  await saveConfig(dir, { secrets: true, dependencies: true, hygiene: true, dataFlow: true });
  await saveConfig(dir, { secrets: false, dependencies: true, hygiene: true, dataFlow: true });
  const gitignore = readFileSync(join(dir, ".gitignore"), "utf-8");
  const occurrences = gitignore.split("\n").filter((l) => l.trim() === ".codevet/").length;
  assert.equal(occurrences, 1);
  rmSync(dir, { recursive: true, force: true });
});
