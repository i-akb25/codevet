// Catches errors from any route, logs full details server-side, returns
// only a generic message to the client. Users never see stack traces,
// file paths, or raw database errors — but nothing is lost for debugging.
//
//   app.use(errorHandler); // must be the LAST app.use() call

function errorHandler(err, req, res, next) {
  // Full details go to your real logger — replace console.error with
  // your structured logger (pino, winston, etc.) in production.
  console.error({
    message: err.message,
    stack: err.stack,
    path: req.path,
    method: req.method,
    timestamp: new Date().toISOString(),
  });

  const statusCode = err.statusCode || 500;

  // Generic message only — never err.message or err.stack to the client,
  // since that can leak file paths, DB schema, or internal logic.
  const publicMessage =
    statusCode < 500 && err.publicMessage
      ? err.publicMessage
      : "Something went wrong. Please try again.";

  res.status(statusCode).json({ error: publicMessage });
}

module.exports = errorHandler;
