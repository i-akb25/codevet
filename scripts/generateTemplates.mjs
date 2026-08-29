// Regenerates the human-browsable templates/ folder from
// src/fixLibrary/templates.ts — the single source of truth. Run via
// `npm run generate-templates`. Never hand-edit files under templates/
// directly; edit templates.ts and regenerate.
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  HELMET_CONFIG,
  CORS_CONFIG,
  RATE_LIMITER,
  ACCOUNT_BACKOFF,
  ERROR_HANDLER,
  HASH_PASSWORD,
  JWT_TOKEN,
  VALIDATION_SCHEMA,
  ENV_EXAMPLE,
  SECURITY_CHECK_WORKFLOW,
  PRE_COMMIT_HOOK,
  FILE_UPLOAD,
  RLS_ENABLE,
} from "../dist/fixLibrary/templates.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..", "templates");

const FILES = [
  ["security/helmet.config.js", HELMET_CONFIG],
  ["security/cors.config.js", CORS_CONFIG],
  ["security/rateLimiter.middleware.js", RATE_LIMITER],
  ["security/accountBackoff.js", ACCOUNT_BACKOFF],
  ["security/errorHandler.middleware.js", ERROR_HANDLER],
  ["security/auth/hashPassword.js", HASH_PASSWORD],
  ["security/auth/generateToken.js", JWT_TOKEN],
  ["security/validation/authSchemas.js", VALIDATION_SCHEMA],
  [".env.example", ENV_EXAMPLE],
  [".github/workflows/security-check.yml", SECURITY_CHECK_WORKFLOW],
  [".husky/pre-commit", PRE_COMMIT_HOOK],
  ["security/fileUpload.middleware.js", FILE_UPLOAD],
  ["enable-rls.sql", RLS_ENABLE],
];

for (const [relativePath, content] of FILES) {
  const fullPath = join(ROOT, relativePath);
  await mkdir(dirname(fullPath), { recursive: true });
  await writeFile(fullPath, content);
  console.log(`wrote templates/${relativePath}`);
}
