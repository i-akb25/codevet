// Runs inside GitHub Actions after `codevet scan --json`. Formats the
// report as a Markdown comment and posts it to the PR via the GitHub REST
// API using fetch() — no @actions/github or @actions/core dependency,
// since this only needs one API call and pulling in the full toolkit
// isn't justified for that (matches the "every dependency must justify
// itself" rule).
//
// Required env vars (all provided automatically inside a GitHub Actions
// PR-triggered workflow, except CODEVET_REPORT_PATH which the workflow sets):
//   GITHUB_TOKEN          - auto-provided by Actions
//   GITHUB_REPOSITORY     - "owner/repo", auto-provided
//   GITHUB_EVENT_PATH     - path to the event payload JSON, auto-provided
//   CODEVET_REPORT_PATH   - path to the JSON report written by `codevet scan --json`

import { readFile } from "node:fs/promises";

function severityEmoji(severity) {
  if (severity === "critical" || severity === "high") return "🔴";
  if (severity === "moderate") return "🟠";
  return "🟡";
}

function formatComment(report) {
  const lines = ["## CodeVet security scan", ""];

  if (report.secrets.length === 0 && report.dependencies.length === 0 && report.hygiene.length === 0) {
    lines.push("✔ No issues found by CodeVet's current checks.");
    return lines.join("\n");
  }

  if (report.secrets.length > 0) {
    lines.push(`### 🔴 ${report.secrets.length} exposed secret(s)`, "");
    for (const s of report.secrets) {
      lines.push(`- **${s.file}:${s.line}** — ${s.description}`);
    }
    lines.push("");
  }

  if (report.dependencies.length > 0) {
    lines.push(`### Dependency vulnerabilities`, "");
    for (const d of report.dependencies) {
      lines.push(
        `- ${severityEmoji(d.severity)} **${d.packageName}** (${d.severity}${d.isDirect ? "" : ", transitive"}) — ${d.advisories[0].title}`,
      );
    }
    lines.push("");
  }

  if (report.hygiene.length > 0) {
    lines.push(`### Missing security middleware`, "");
    for (const h of report.hygiene) {
      const marker = h.confidence === "high" ? "🔴" : "🟡 (advisory)";
      lines.push(`- ${marker} **${h.title}** — ${h.description}`);
    }
    lines.push("");
  }

  lines.push(
    "---",
    "_Run `npx codevet scan` locally for full details and suggested fix code. This comment is generated automatically on every push to this PR — see [CodeVet](https://github.com/codevet/codevet)._",
  );

  return lines.join("\n");
}

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  const reportPath = process.env.CODEVET_REPORT_PATH;

  if (!token || !repo || !eventPath || !reportPath) {
    console.error(
      "[codevet-pr-comment] Missing required env var(s) — this script is meant to run inside a GitHub Actions PR workflow.",
    );
    process.exit(1);
  }

  const event = JSON.parse(await readFile(eventPath, "utf-8"));
  const prNumber = event.pull_request?.number ?? event.number;
  if (!prNumber) {
    console.log("[codevet-pr-comment] Not a pull request event — skipping comment.");
    return;
  }

  const report = JSON.parse(await readFile(reportPath, "utf-8"));
  const body = formatComment(report);

  const response = await fetch(
    `https://api.github.com/repos/${repo}/issues/${prNumber}/comments`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ body }),
    },
  );

  if (!response.ok) {
    console.error(`[codevet-pr-comment] Failed to post comment: ${response.status} ${await response.text()}`);
    process.exit(1);
  }

  console.log("[codevet-pr-comment] Comment posted successfully.");
}

main().catch((err) => {
  console.error("[codevet-pr-comment] Error:", err);
  process.exit(1);
});
