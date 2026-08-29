// security/rateLimiter.middleware.js
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
