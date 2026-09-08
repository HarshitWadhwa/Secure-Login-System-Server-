const rateLimit = require('express-rate-limit');
const validator = require('validator');

// Rate limiting middleware to prevent brute-force attacks and credential stuffing
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Max 10 attempts per window per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many login attempts from this IP. Please try again after 15 minutes.'
  }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 15, // Max 15 accounts per hour per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many registration requests from this IP. Please try again later.'
  }
});

const twoFactorLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 6, // Max 6 2FA attempts
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many 2FA verification attempts. Please wait 10 minutes before retrying.'
  }
});

// Authentication Guard: Ensures user has an active, authenticated session
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({
      authenticated: false,
      error: 'Authentication required. Please log in.'
    });
  }
  next();
}

// Pending 2FA Guard: Used during login when password is correct but 2FA token is pending
function requirePending2FA(req, res, next) {
  if (!req.session || !req.session.pending2FAUserId) {
    return res.status(401).json({
      error: 'No 2FA verification pending. Please start login again.'
    });
  }
  next();
}

// Comprehensive Input Validation Middleware
function validateRegisterInput(req, res, next) {
  let { username, email, password, confirmPassword } = req.body;

  // Type & Existence checks
  if (!username || !email || !password || !confirmPassword) {
    return res.status(400).json({ error: 'All fields (username, email, password, confirmPassword) are required.' });
  }

  // Sanitize string inputs
  username = String(username).trim();
  email = String(email).trim().toLowerCase();
  password = String(password);
  confirmPassword = String(confirmPassword);

  // Validate Username: Alphanumeric and underscores/hyphens, 3 to 30 characters
  const usernameRegex = /^[a-zA-Z0-9_-]{3,30}$/;
  if (!usernameRegex.test(username)) {
    return res.status(400).json({
      error: 'Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens.'
    });
  }

  // Validate Email
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Please provide a valid email address.' });
  }

  // Validate Password Confirmation
  if (password !== confirmPassword) {
    return res.status(400).json({ error: 'Password and confirmation do not match.' });
  }

  // Strong Password Policy:
  // - Minimum 8 characters
  // - At least 1 lowercase letter
  // - At least 1 uppercase letter
  // - At least 1 digit
  // - At least 1 special character
  const passwordErrors = [];
  if (password.length < 8) passwordErrors.push('at least 8 characters long');
  if (password.length > 128) passwordErrors.push('no longer than 128 characters');
  if (!/[a-z]/.test(password)) passwordErrors.push('at least one lowercase letter');
  if (!/[A-Z]/.test(password)) passwordErrors.push('at least one uppercase letter');
  if (!/[0-9]/.test(password)) passwordErrors.push('at least one number');
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password)) {
    passwordErrors.push('at least one special symbol (e.g. !@#$%^&*)');
  }

  if (passwordErrors.length > 0) {
    return res.status(400).json({
      error: `Password must satisfy: ${passwordErrors.join(', ')}.`
    });
  }

  // Attach sanitized fields to req.body
  req.body.username = username;
  req.body.email = email;
  req.body.password = password;

  next();
}

function validateLoginInput(req, res, next) {
  let { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Username/Email and Password are required.' });
  }

  req.body.identifier = String(identifier).trim();
  req.body.password = String(password);

  next();
}

function validateTwoFactorToken(req, res, next) {
  const { token } = req.body;
  if (!token || !/^\d{6}$/.test(String(token).trim())) {
    return res.status(400).json({ error: 'Please enter a valid 6-digit verification code.' });
  }
  req.body.token = String(token).trim();
  next();
}

module.exports = {
  loginLimiter,
  registerLimiter,
  twoFactorLimiter,
  requireAuth,
  requirePending2FA,
  validateRegisterInput,
  validateLoginInput,
  validateTwoFactorToken
};
