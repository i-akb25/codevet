// security/auth/hashPassword.js
const argon2 = require('argon2');

async function hashPassword(plainPassword) {
  return argon2.hash(plainPassword);
}

async function verifyPassword(plainPassword, hash) {
  return argon2.verify(hash, plainPassword);
}

module.exports = { hashPassword, verifyPassword };
