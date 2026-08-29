// security/auth/generateToken.js
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
