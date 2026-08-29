// security/cors.config.js
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
