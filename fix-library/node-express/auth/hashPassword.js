// Password hashing — argon2 (winner of the Password Hashing Competition,
// stronger than bcrypt against GPU-based cracking). Never store plaintext.
//
//   const { hashPassword, verifyPassword } = require('./security/auth/hashPassword');
//
// Requires: npm install argon2

const argon2 = require("argon2");

async function hashPassword(plainTextPassword) {
  return argon2.hash(plainTextPassword, {
    type: argon2.argon2id, // resists both GPU cracking and side-channel attacks
  });
}

async function verifyPassword(plainTextPassword, hash) {
  try {
    return await argon2.verify(hash, plainTextPassword);
  } catch {
    // argon2.verify throws on a malformed hash rather than returning false —
    // treat that the same as "doesn't match" instead of crashing the request.
    return false;
  }
}

module.exports = { hashPassword, verifyPassword };
