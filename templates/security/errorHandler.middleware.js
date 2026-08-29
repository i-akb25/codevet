// security/errorHandler.middleware.js
// Must be registered LAST, after all routes.
module.exports = function errorHandler(err, req, res, next) {
  // Full details go to server-side logs — never to the client.
  console.error(err);

  // The client only ever sees a generic message, never a stack trace,
  // file path, or raw database error.
  res.status(err.statusCode || 500).json({
    error: 'Something went wrong. Please try again.',
  });
};

// Usage: app.use(errorHandler); // after every other app.use()/route
