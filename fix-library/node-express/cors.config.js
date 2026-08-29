// CORS with a whitelist — never use `origin: '*'` if your API sends
// credentials (cookies, auth headers), since that combination lets any
// website read authenticated responses on a victim's behalf.
//
//   const corsConfig = require('./security/cors.config');
//   app.use(corsConfig);
//
// Requires: npm install cors
// Set ALLOWED_ORIGINS in your .env as a comma-separated list.

const cors = require("cors");

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

module.exports = cors({
  origin(origin, callback) {
    // Allow requests with no origin (server-to-server, curl, mobile apps)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    callback(new Error(`Origin ${origin} not allowed by CORS`));
  },
  credentials: true,
});
