const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { dbService } = require('./db');

// BCrypt Salt Rounds: 12 provides high cryptographic resistance against brute force & rainbow tables
const BCRYPT_SALT_ROUNDS = 12;

// Dummy hash for constant-time comparison when user doesn't exist (prevents timing-based user enumeration)
const DUMMY_HASH = '$2a$12$e8YvA1eX9P.w6HjZgW4mXe13pG1q63QnZ52E5UfF1r9yE7M4r8EGy';

/**
 * Hash a plaintext password using bcrypt
 */
async function hashPassword(password) {
  return await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
}

/**
 * Timing-safe password verification
 */
async function comparePassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

/**
 * Register a new user
 */
async function registerUser({ username, email, password }, req) {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  // Check if username is already taken
  const existingUsername = dbService.findUserByUsername(username);
  if (existingUsername) {
    throw { status: 409, message: 'Username is already registered.' };
  }

  // Check if email is already registered
  const existingEmail = dbService.findUserByEmail(email);
  if (existingEmail) {
    throw { status: 409, message: 'An account with this email already exists.' };
  }

  // Hash password using bcrypt
  const passwordHash = await hashPassword(password);

  // Insert user via parameterized query (100% immune to SQL injection)
  const userId = dbService.createUser(username, email, passwordHash);

  // Audit log
  dbService.logSecurityEvent(userId, 'ACCOUNT_CREATED', ip, userAgent);

  return {
    id: userId,
    username,
    email
  };
}

/**
 * Authenticate user credentials
 */
async function authenticateUser({ identifier, password }, req) {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  // Query database using parameterized query
  const user = dbService.findUserByIdentifier(identifier);

  if (!user) {
    // Perform dummy comparison to equalize response time and prevent timing side-channel attacks
    await bcrypt.compare(password, DUMMY_HASH);
    throw { status: 401, message: 'Invalid username/email or password.' };
  }

  // Verify password with bcrypt
  const isMatch = await comparePassword(password, user.password_hash);
  if (!isMatch) {
    dbService.logSecurityEvent(user.id, 'LOGIN_FAILED_BAD_PASSWORD', ip, userAgent);
    throw { status: 401, message: 'Invalid username/email or password.' };
  }

  // If Two-Factor Authentication is enabled, require 2FA verification step
  if (user.two_factor_enabled && user.two_factor_secret) {
    req.session.pending2FAUserId = user.id;
    dbService.logSecurityEvent(user.id, '2FA_CHALLENGE_ISSUED', ip, userAgent);
    return {
      requires2FA: true,
      message: 'Please provide your 6-digit Two-Factor Authentication code.'
    };
  }

  // 2FA not enabled: complete login, regenerate session to prevent session fixation
  await regenerateSession(req);
  req.session.userId = user.id;
  dbService.updateLastLogin(user.id);
  dbService.logSecurityEvent(user.id, 'LOGIN_SUCCESS', ip, userAgent);

  return {
    requires2FA: false,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      two_factor_enabled: Boolean(user.two_factor_enabled),
      created_at: user.created_at,
      last_login: user.last_login
    }
  };
}

/**
 * Verify 2FA token during login flow
 */
async function verify2FALogin(token, req) {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  const pendingUserId = req.session.pending2FAUserId;

  if (!pendingUserId) {
    throw { status: 400, message: 'No 2FA verification currently pending.' };
  }

  const user = dbService.findUserByIdWithSecrets(pendingUserId);
  if (!user || !user.two_factor_enabled || !user.two_factor_secret) {
    delete req.session.pending2FAUserId;
    throw { status: 400, message: 'Invalid 2FA state. Please login again.' };
  }

  // Verify TOTP token with +/- 1 time step window for clock drift tolerance
  const verified = speakeasy.totp.verify({
    secret: user.two_factor_secret,
    encoding: 'base32',
    token: token.trim(),
    window: 1
  });

  if (!verified) {
    dbService.logSecurityEvent(user.id, '2FA_LOGIN_FAILED', ip, userAgent);
    throw { status: 401, message: 'Invalid or expired 2FA verification code.' };
  }

  // 2FA code is valid! Clean up pending state & establish authenticated session
  delete req.session.pending2FAUserId;
  await regenerateSession(req);
  req.session.userId = user.id;
  dbService.updateLastLogin(user.id);
  dbService.logSecurityEvent(user.id, 'LOGIN_SUCCESS_2FA', ip, userAgent);

  return {
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      two_factor_enabled: true,
      created_at: user.created_at,
      last_login: user.last_login
    }
  };
}

/**
 * Generate 2FA Secret and QR Code for account setup
 */
async function generate2FASecret(userId) {
  const user = dbService.findUserById(userId);
  if (!user) {
    throw { status: 404, message: 'User not found.' };
  }

  // Generate TOTP secret
  const secret = speakeasy.generateSecret({
    length: 20,
    name: `SecureApp (${user.username})`,
    issuer: 'SecureLoginSystem'
  });

  // Temporarily store secret in DB until verified
  dbService.set2FASecret(userId, secret.base32);

  // Generate QR code data URL
  const qrCodeDataUrl = await QRCode.toDataURL(secret.otpauth_url);

  return {
    secret: secret.base32,
    otpauthUrl: secret.otpauth_url,
    qrCode: qrCodeDataUrl
  };
}

/**
 * Verify code and enable 2FA
 */
async function verifyAndEnable2FA(userId, token, req) {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  const user = dbService.findUserByIdWithSecrets(userId);

  if (!user || !user.two_factor_secret) {
    throw { status: 400, message: '2FA setup was not initiated. Please generate a QR code first.' };
  }

  const verified = speakeasy.totp.verify({
    secret: user.two_factor_secret,
    encoding: 'base32',
    token: token.trim(),
    window: 1
  });

  if (!verified) {
    throw { status: 400, message: 'Invalid verification code. Please check your authenticator app.' };
  }

  dbService.enable2FA(userId);
  dbService.logSecurityEvent(userId, '2FA_ENABLED', ip, userAgent);

  return {
    success: true,
    message: 'Two-Factor Authentication has been successfully enabled!'
  };
}

/**
 * Disable 2FA with password confirmation
 */
async function disable2FA(userId, password, req) {
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  const user = dbService.findUserByIdWithSecrets(userId);

  if (!user) {
    throw { status: 404, message: 'User not found.' };
  }

  // Require current password to disable 2FA
  const isMatch = await comparePassword(password, user.password_hash);
  if (!isMatch) {
    throw { status: 401, message: 'Incorrect password. Unable to disable 2FA.' };
  }

  dbService.disable2FA(userId);
  dbService.logSecurityEvent(userId, '2FA_DISABLED', ip, userAgent);

  return {
    success: true,
    message: 'Two-Factor Authentication has been disabled.'
  };
}

/**
 * Terminate user session and clear cookies
 */
function logoutUser(req, res) {
  const userId = req.session ? req.session.userId : null;
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];

  if (userId) {
    dbService.logSecurityEvent(userId, 'LOGOUT', ip, userAgent);
  }

  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      res.clearCookie('connect.sid', { path: '/' });
      res.json({ success: true, message: 'Logged out successfully.' });
    });
  } else {
    res.json({ success: true, message: 'Already logged out.' });
  }
}

/**
 * Helper to regenerate session (session fixation defense)
 */
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

module.exports = {
  hashPassword,
  comparePassword,
  registerUser,
  authenticateUser,
  verify2FALogin,
  generate2FASecret,
  verifyAndEnable2FA,
  disable2FA,
  logoutUser
};
