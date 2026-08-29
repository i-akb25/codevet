/**
 * Real, working code templates shown as suggested fixes. Each one is
 * plain, dependency-minimal Express middleware — matches the "no
 * unnecessary abstraction" engineering rule. These are not generated per
 * finding; they're static, reviewed content, versioned here so updates
 * propagate to every future scan instead of going stale in someone's repo.
 */

export const HELMET_CONFIG = `// security/helmet.config.js
const helmet = require('helmet');

module.exports = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
});

// Usage: app.use(require('./security/helmet.config'));
`;

export const CORS_CONFIG = `// security/cors.config.js
const cors = require('cors');

// Replace with your actual allowed origins — never use '*' once you have
// real users, since it lets any website read your API's responses.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);

module.exports = cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
});

// Usage: app.use(require('./security/cors.config'));
// .env: ALLOWED_ORIGINS=https://yourapp.com,https://staging.yourapp.com
`;

export const ACCOUNT_BACKOFF = `// security/accountBackoff.js
// Per-account exponential backoff — complements a per-IP rate limiter,
// since an attacker distributing attempts across many IPs would otherwise
// bypass IP-based limiting entirely. Uses exponential backoff (delay
// doubles each failed attempt) rather than a hard lockout, since hard
// lockouts let an attacker lock a real user out of their own account (a
// denial-of-service against your own users).
//
//   const { checkAccountBackoff, recordFailedAttempt, recordSuccessfulAttempt } = require('./security/accountBackoff');
//
//   app.post('/login', async (req, res) => {
//     const { email } = req.body;
//     const backoff = checkAccountBackoff(email);
//     if (backoff.blocked) {
//       return res.status(429).json({ error: \`Try again in \${backoff.retryAfterSeconds}s\` });
//     }
//     const valid = await verifyPassword(...);
//     if (!valid) {
//       recordFailedAttempt(email);
//       return res.status(401).json({ error: 'Invalid credentials' });
//     }
//     recordSuccessfulAttempt(email);
//     // ...issue token
//   });
//
// In-memory by default — fine for a single instance. For multi-instance
// deployments, swap the Map for Redis (same interface, different backing
// store) so backoff state is shared across instances.

const attempts = new Map();

const BASE_DELAY_MS = parseInt(process.env.AUTH_BACKOFF_BASE_MS ?? '1000', 10);
const MAX_DELAY_MS = parseInt(process.env.AUTH_BACKOFF_MAX_MS ?? '300000', 10);
const RESET_AFTER_MS = parseInt(process.env.AUTH_BACKOFF_RESET_MS ?? '3600000', 10);

function checkAccountBackoff(accountKey) {
  const record = attempts.get(accountKey);
  if (!record) return { blocked: false };

  const elapsedSinceLastAttempt = Date.now() - record.lastAttemptAt;
  if (elapsedSinceLastAttempt > RESET_AFTER_MS) {
    attempts.delete(accountKey);
    return { blocked: false };
  }

  const requiredDelay = Math.min(BASE_DELAY_MS * 2 ** record.failCount, MAX_DELAY_MS);

  if (elapsedSinceLastAttempt < requiredDelay) {
    return { blocked: true, retryAfterSeconds: Math.ceil((requiredDelay - elapsedSinceLastAttempt) / 1000) };
  }

  return { blocked: false };
}

function recordFailedAttempt(accountKey) {
  const record = attempts.get(accountKey) ?? { failCount: 0, lastAttemptAt: 0 };
  record.failCount += 1;
  record.lastAttemptAt = Date.now();
  attempts.set(accountKey, record);
}

function recordSuccessfulAttempt(accountKey) {
  attempts.delete(accountKey);
}

module.exports = { checkAccountBackoff, recordFailedAttempt, recordSuccessfulAttempt };
`;

export const RATE_LIMITER = `// security/rateLimiter.middleware.js
const rateLimit = require('express-rate-limit');

// Stricter limits on auth routes, looser on general API traffic — apply
// the right one per route rather than one blanket limiter for everything.
function makeLimiter({ windowMs, max }) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
  });
}

module.exports = {
  authLimiter: makeLimiter({
    windowMs: Number(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: Number(process.env.AUTH_RATE_LIMIT_MAX) || 5,
  }),
  publicLimiter: makeLimiter({
    windowMs: Number(process.env.PUBLIC_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: Number(process.env.PUBLIC_RATE_LIMIT_MAX) || 100,
  }),
  authenticatedLimiter: makeLimiter({
    windowMs: Number(process.env.AUTHED_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: Number(process.env.AUTHED_RATE_LIMIT_MAX) || 300,
  }),
};

// Usage: app.use('/login', authLimiter); app.use('/api', publicLimiter);
// Thresholds are env-configurable, not hardcoded, per the checklist.
`;

export const ERROR_HANDLER = `// security/errorHandler.middleware.js
// Must be registered LAST, after all routes.
module.exports = function errorHandler(err, req, res, next) {
  // Full details go to server-side logs — never to the client.
  console.error(err);

  // The client only ever sees a generic message, never a stack trace,
  // file path, or raw database error.
  res.status(err.statusCode || 500).json({
    error: 'Something went wrong. Please try again.',
  });
};

// Usage: app.use(errorHandler); // after every other app.use()/route
`;

export const HASH_PASSWORD = `// security/auth/hashPassword.js
const argon2 = require('argon2');

async function hashPassword(plainPassword) {
  return argon2.hash(plainPassword);
}

async function verifyPassword(plainPassword, hash) {
  return argon2.verify(hash, plainPassword);
}

module.exports = { hashPassword, verifyPassword };
`;

export const JWT_TOKEN = `// security/auth/generateToken.js
const jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  throw new Error('JWT_SECRET is not set — refusing to start without it.');
}

function generateToken(payload, expiresIn = '15m') {
  return jwt.sign(payload, SECRET, { expiresIn });
}

function verifyToken(token) {
  return jwt.verify(token, SECRET); // throws on invalid/expired
}

module.exports = { generateToken, verifyToken };
// Pair a short-lived access token with a separate, longer-lived refresh
// token stored server-side (or httpOnly cookie) — never a single
// long-lived token for everything.
`;

export const VALIDATION_SCHEMA = `// security/validation/authSchemas.js
const { z } = require('zod');

// Strict schema: type, length, and format all enforced. Anything that
// doesn't match is REJECTED, not silently sanitized/escaped.
const signupSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(12).max(128),
});

const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(1).max(128),
});

module.exports = { signupSchema, loginSchema };
// Usage: const data = signupSchema.parse(req.body); // throws on invalid input
`;

export const ENV_EXAMPLE = `# .env.example — copy to .env and fill in real values. Never commit .env itself.
JWT_SECRET=
ALLOWED_ORIGINS=https://yourapp.com
AUTH_RATE_LIMIT_MAX=5
PUBLIC_RATE_LIMIT_MAX=100
DATABASE_URL=
`;

export const SECURITY_CHECK_WORKFLOW = `# .github/workflows/security-check.yml
name: security-check
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci
      - run: npm audit --audit-level=high
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}
`;

export const PRE_COMMIT_HOOK = `#!/usr/bin/env sh
# .husky/pre-commit — requires: npm install -D husky && npx husky init
npx gitleaks protect --staged --no-banner || {
  echo "Blocked: gitleaks found a potential secret in your staged changes.";
  exit 1;
}
`;

export const FILE_UPLOAD = `// security/fileUpload.middleware.js
const multer = require('multer');
const path = require('node:path');
const crypto = require('node:crypto');

const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf']);
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// Store outside the web root — never somewhere a webserver would execute
// an uploaded file (e.g. never inside a directory served with script
// execution enabled).
const UPLOAD_DIR = path.join(process.cwd(), 'private-uploads');

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename(req, file, cb) {
    // Never trust the original filename — generate a random one instead.
    cb(null, crypto.randomBytes(16).toString('hex'));
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter(req, file, cb) {
    if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
      return cb(new Error('Unsupported file type'));
    }
    cb(null, true);
  },
});

// IMPORTANT: fileFilter only checks the client-provided mimetype header,
// which can be spoofed. After upload, verify actual file content with a
// library like 'file-type' (reads magic bytes) before trusting it.

module.exports = { upload, UPLOAD_DIR };
// Usage: app.post('/upload', upload.single('file'), uploadHandler);
`;

export const RLS_ENABLE = `-- Enable Row Level Security on a table, then add a policy.
-- Without RLS, the public anon key can read/write this table directly —
-- this is the #1 cause of drained/defaced Supabase-backed apps.

ALTER TABLE your_table_name ENABLE ROW LEVEL SECURITY;

-- Example: users can only read their own rows.
CREATE POLICY "Users can read their own rows"
  ON your_table_name
  FOR SELECT
  USING (auth.uid() = user_id);

-- Repeat ALTER TABLE ... ENABLE ROW LEVEL SECURITY for every table —
-- there are no exceptions. A table with RLS enabled but no policies
-- denies all access by default, which is a safe starting point.
`;

export interface FixTemplate {
  id: string;
  title: string;
  code: string;
}

export const FIX_TEMPLATES: Record<string, FixTemplate> = {
  helmet: { id: "helmet", title: "security/helmet.config.js", code: HELMET_CONFIG },
  cors: { id: "cors", title: "security/cors.config.js", code: CORS_CONFIG },
  rateLimit: { id: "rateLimit", title: "security/rateLimiter.middleware.js", code: RATE_LIMITER },
  accountBackoff: { id: "accountBackoff", title: "security/accountBackoff.js", code: ACCOUNT_BACKOFF },
  errorHandler: { id: "errorHandler", title: "security/errorHandler.middleware.js", code: ERROR_HANDLER },
  hashPassword: { id: "hashPassword", title: "security/auth/hashPassword.js", code: HASH_PASSWORD },
  jwt: { id: "jwt", title: "security/auth/generateToken.js", code: JWT_TOKEN },
  validation: { id: "validation", title: "security/validation/authSchemas.js", code: VALIDATION_SCHEMA },
  envExample: { id: "envExample", title: ".env.example", code: ENV_EXAMPLE },
  ciWorkflow: { id: "ciWorkflow", title: ".github/workflows/security-check.yml", code: SECURITY_CHECK_WORKFLOW },
  preCommit: { id: "preCommit", title: ".husky/pre-commit", code: PRE_COMMIT_HOOK },
  fileUpload: { id: "fileUpload", title: "security/fileUpload.middleware.js", code: FILE_UPLOAD },
  rlsEnable: { id: "rlsEnable", title: "enable-rls.sql", code: RLS_ENABLE },
};
