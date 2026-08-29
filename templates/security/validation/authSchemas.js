// security/validation/authSchemas.js
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
