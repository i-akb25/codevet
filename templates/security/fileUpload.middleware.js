// security/fileUpload.middleware.js
const multer = require('multer');
const path = require('node:path');
const crypto = require('node:crypto');

const ALLOWED_MIME_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'application/pdf']);
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

// Store outside the web root — never somewhere a webserver would execute
// an uploaded file (e.g. never inside a directory served with script
// execution enabled).
const UPLOAD_DIR = path.join(process.cwd(), 'private-uploads');

const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename(req, file, cb) {
    // Never trust the original filename — generate a random one instead.
    cb(null, crypto.randomBytes(16).toString('hex'));
  },
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter(req, file, cb) {
    if (!ALLOWED_MIME_TYPES.has(file.mimetype)) {
      return cb(new Error('Unsupported file type'));
    }
    cb(null, true);
  },
});

// IMPORTANT: fileFilter only checks the client-provided mimetype header,
// which can be spoofed. After upload, verify actual file content with a
// library like 'file-type' (reads magic bytes) before trusting it.

module.exports = { upload, UPLOAD_DIR };
// Usage: app.post('/upload', upload.single('file'), uploadHandler);
