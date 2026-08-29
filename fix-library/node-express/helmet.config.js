// Secure HTTP headers — prevents XSS, clickjacking, MIME-sniffing attacks.
// Import and apply this BEFORE your routes.
//
//   const helmetConfig = require('./security/helmet.config');
//   app.use(helmetConfig);
//
// Requires: npm install helmet

const helmet = require("helmet");

module.exports = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"], // relax further only if you have a real reason
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false, // enable only if you understand the COEP tradeoffs for your app
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
});
