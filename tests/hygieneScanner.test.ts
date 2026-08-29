import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runHygieneScan } from "../dist/scanners/hygieneScanner.js";

function makeExpressProject(serverContent: string, deps: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "t", dependencies: { express: "4.19.2", ...deps } }),
  );
  writeFileSync(join(dir, "server.js"), serverContent);
  return dir;
}

test("flags missing helmet on an Express project", async () => {
  const dir = makeExpressProject("const express = require('express');");
  const findings = await runHygieneScan(dir);
  assert.ok(findings.some((f) => f.id === "missing-helmet"));
  rmSync(dir, { recursive: true, force: true });
});

test("does not flag missing helmet when it's actually installed", async () => {
  const dir = makeExpressProject("", { helmet: "7.1.0" });
  const findings = await runHygieneScan(dir);
  assert.ok(!findings.some((f) => f.id === "missing-helmet"));
  rmSync(dir, { recursive: true, force: true });
});

test("does not run Express checks on a non-Express project", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "t" }));
  const findings = await runHygieneScan(dir);
  assert.equal(findings.length, 0);
  rmSync(dir, { recursive: true, force: true });
});

// Regression test — this exact pattern was missed in manual testing before
// the regex was fixed to account for a chained .status() call.
test("catches error-leak pattern with res.status(500).json(err.message)", async () => {
  const dir = makeExpressProject(
    `app.get('/x', (req, res) => { res.status(500).json({ error: err.message, stack: err.stack }); });`,
  );
  const findings = await runHygieneScan(dir);
  assert.ok(findings.some((f) => f.id === "error-leak"));
  rmSync(dir, { recursive: true, force: true });
});

test("does not flag a properly handled error response", async () => {
  const dir = makeExpressProject(
    `app.get('/x', (req, res) => { res.status(500).json({ error: 'Something went wrong' }); });`,
  );
  const findings = await runHygieneScan(dir);
  assert.ok(!findings.some((f) => f.id === "error-leak"));
  rmSync(dir, { recursive: true, force: true });
});

test("flags CORS wildcard usage", async () => {
  const dir = makeExpressProject(`app.use(cors());`, { cors: "2.8.5" });
  const findings = await runHygieneScan(dir);
  assert.ok(findings.some((f) => f.id === "cors-wildcard"));
  rmSync(dir, { recursive: true, force: true });
});

test("flags a Supabase table with no matching ENABLE ROW LEVEL SECURITY", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "t", dependencies: { "@supabase/supabase-js": "2.0.0" } }),
  );
  mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
  writeFileSync(
    join(dir, "supabase", "migrations", "001_init.sql"),
    `CREATE TABLE posts (id uuid PRIMARY KEY);`,
  );
  const findings = await runHygieneScan(dir);
  assert.ok(findings.some((f) => f.id === "supabase-rls-missing-posts"));
  rmSync(dir, { recursive: true, force: true });
});

test("does not flag a Supabase table that has RLS enabled in the same file", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "t", dependencies: { "@supabase/supabase-js": "2.0.0" } }),
  );
  mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
  writeFileSync(
    join(dir, "supabase", "migrations", "001_init.sql"),
    `CREATE TABLE profiles (id uuid PRIMARY KEY);\nALTER TABLE profiles ENABLE ROW LEVEL SECURITY;`,
  );
  const findings = await runHygieneScan(dir);
  assert.ok(!findings.some((f) => f.id === "supabase-rls-missing-profiles"));
  rmSync(dir, { recursive: true, force: true });
});

test("RLS check runs even on a non-Express project (e.g. Next.js + Supabase)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "codevet-test-"));
  writeFileSync(
    join(dir, "package.json"),
    JSON.stringify({ name: "t", dependencies: { next: "14.0.0", "@supabase/supabase-js": "2.0.0" } }),
  );
  mkdirSync(join(dir, "supabase", "migrations"), { recursive: true });
  writeFileSync(
    join(dir, "supabase", "migrations", "001_init.sql"),
    `CREATE TABLE posts (id uuid PRIMARY KEY);`,
  );
  const findings = await runHygieneScan(dir);
  assert.ok(findings.some((f) => f.id === "supabase-rls-missing-posts"));
  rmSync(dir, { recursive: true, force: true });
});
