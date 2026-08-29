// Tiered rate limiting — stricter on auth routes, moderate on public
// endpoints, looser on authenticated user actions. All thresholds are
// configurable via env vars, not hardcoded, per the "make thresholds
// configurable" requirement.
//
//   const { authLimiter, publicLimiter, userLimiter } = require('./security/rateLimiter.middleware');
//   app.use('/auth', authLimiter);
//   app.use('/api/public', publicLimiter);
//   app.use('/api/user', userLimiter);
//
// Requires: npm install express-rate-limit

const rateLimit = require("express-rate-limit");

function envInt(name, fallback) {
  const value = parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(value) ? value : fallback;
}

// Auth routes (login, signup, password reset): strict, per-IP, since these
// are the routes brute-force attacks actually target.
const authLimiter = rateLimit({
  windowMs: envInt("AUTH_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000), // 15 min
  max: envInt("AUTH_RATE_LIMIT_MAX", 5),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Please try again later." },
});

// Public endpoints: moderate — enough headroom for normal use, still a
// real ceiling against scraping/spam.
const publicLimiter = rateLimit({
  windowMs: envInt("PUBLIC_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
  max: envInt("PUBLIC_RATE_LIMIT_MAX", 100),
  standardHeaders: true,
  legacyHeaders: false,
});

// Authenticated user actions: looser, since these callers are already
// identified and less likely to be anonymous abuse.
const userLimiter = rateLimit({
  windowMs: envInt("USER_RATE_LIMIT_WINDOW_MS", 15 * 60 * 1000),
  max: envInt("USER_RATE_LIMIT_MAX", 300),
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = { authLimiter, publicLimiter, userLimiter };
