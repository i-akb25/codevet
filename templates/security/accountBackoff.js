// security/accountBackoff.js
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
//       return res.status(429).json({ error: `Try again in ${backoff.retryAfterSeconds}s` });
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
