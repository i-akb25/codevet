import { existsSync } from "node:fs";
import { join } from "node:path";

export type Stack = "node" | "python" | "android" | "ios";

interface StackSignal {
  stack: Stack;
  file: string;
}

const SIGNALS: StackSignal[] = [
  { stack: "node", file: "package.json" },
  { stack: "python", file: "requirements.txt" },
  { stack: "python", file: "pyproject.toml" },
  { stack: "android", file: "build.gradle" },
  { stack: "android", file: "build.gradle.kts" },
  { stack: "ios", file: "Podfile" },
];

export interface DetectedStack {
  stack: Stack;
  matchedOn: string;
}

/**
 * Detects which stacks are present at the root of a project directory.
 * A repo can match more than one stack — that's expected, not an error.
 */
export function detectStack(projectRoot: string): DetectedStack[] {
  const found = new Map<Stack, string>();

  for (const signal of SIGNALS) {
    if (found.has(signal.stack)) continue;
    if (existsSync(join(projectRoot, signal.file))) {
      found.set(signal.stack, signal.file);
    }
  }

  return Array.from(found.entries()).map(([stack, matchedOn]) => ({
    stack,
    matchedOn,
  }));
}
