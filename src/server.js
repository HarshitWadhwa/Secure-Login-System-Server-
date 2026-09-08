require('dotenv').config();
const express = require('express');
const path = require('path');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');

const { dbService } = require('./db');
const {
  registerUser,
  authenticateUser,
  verify2FALogin,
  generate2FASecret,
  verifyAndEnable2FA,
  disable2FA,
  logoutUser
} = require('./auth');

const {
  loginLimiter,
  registerLimiter,
  twoFactorLimiter,
  requireAuth,
  requirePending2FA,
  validateRegisterInput,
  validateLoginInput,
  validateTwoFactorToken
} = require('./middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// Trust proxy if deployed behind a reverse proxy (e.g. Nginx, Heroku)
app.set('trust proxy', 1);

// 1. Security Headers via Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: IS_PROD ? [] : null
      }
    },
    xFrameOptions: { action: 'deny' },
    crossOriginEmbedderPolicy: false
  })
);

// 2. Request body parsing with strict size limits to prevent DoS
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 3. Secure Session Management
app.use(
  session({
    name: '__Host_auth_sid', // Obscures standard 'connect.sid' cookie name
    secret: process.env.SESSION_SECRET || 'dev_secret_key_change_me_in_production_12345',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents client-side scripts from reading the cookie (protects against XSS session theft)
      sameSite: 'lax', // Protects against Cross-Site Request Forgery (CSRF)
      secure: IS_PROD, // In production, cookies are transmitted strictly over HTTPS
      maxAge: 24 * 60 * 60 * 1000 // 24-hour session lifetime
    }
  })
);

// 4. Serve static frontend assets
app.use(express.static(path.join(__dirname, '..', 'public')));

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

// Health Check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    security: {
      passwordHashing: 'bcrypt (Cost 12)',
      sqlProtection: 'Parameterized Statements',
      twoFactorAuth: 'TOTP (RFC 6238)',
      sessionSecurity: 'HttpOnly, SameSite=Lax, Session Fixation Protected'
    }
  });
});

// User Registration
app.post('/api/register', registerLimiter, validateRegisterInput, async (req, res, next) => {
  try {
    const user = await registerUser(req.body, req);
    res.status(201).json({
      success: true,
      message: 'Account successfully registered! You can now log in.',
      user
    });
  } catch (err) {
    next(err);
  }
});

// User Login (Supports standard password login and 2FA challenge flow)
app.post('/api/login', loginLimiter, validateLoginInput, async (req, res, next) => {
  try {
    const result = await authenticateUser(req.body, req);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    next(err);
  }
});

// Verify 2FA Token for pending login
app.post('/api/verify-2fa-login', twoFactorLimiter, requirePending2FA, validateTwoFactorToken, async (req, res, next) => {
  try {
    const result = await verify2FALogin(req.body.token, req);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    next(err);
  }
});

// Logout (Destroys server session and clears client cookie)
app.post('/api/logout', (req, res) => {
  logoutUser(req, res);
});

// Current User Profile & Session status
app.get('/api/me', requireAuth, (req, res) => {
  const user = dbService.findUserById(req.session.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  res.json({
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      two_factor_enabled: Boolean(user.two_factor_enabled),
      created_at: user.created_at,
      last_login: user.last_login
    }
  });
});

// User Security Event Logs (Proactive audit log)
app.get('/api/security-logs', requireAuth, (req, res) => {
  const logs = dbService.getUserSecurityLogs(req.session.userId, 15);
  res.json({ logs });
});

// Generate 2FA Secret and QR Code
app.post('/api/2fa/generate', requireAuth, async (req, res, next) => {
  try {
    const data = await generate2FASecret(req.session.userId);
    res.json({
      success: true,
      ...data
    });
  } catch (err) {
    next(err);
  }
});

// Verify and Enable 2FA
app.post('/api/2fa/verify', requireAuth, twoFactorLimiter, validateTwoFactorToken, async (req, res, next) => {
  try {
    const result = await verifyAndEnable2FA(req.session.userId, req.body.token, req);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// Disable 2FA (requires current password verification)
app.post('/api/2fa/disable', requireAuth, async (req, res, next) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(400).json({ error: 'Current password is required to disable 2FA.' });
    }
    const result = await disable2FA(req.session.userId, password, req);
    res.json(result);
  } catch (err) {
    next(err);
  }
});

// ----------------------------------------------------
// SECURITY DEMONSTRATION & LAB APIS
// ----------------------------------------------------

// Interactive SQL Injection Defense Tester
app.post('/api/demo/sqli-test', (req, res) => {
  const input = req.body.input || "' OR '1'='1";
  const comparison = dbService.demoCompareSqli(input);
  res.json(comparison);
});

// Password Hashing Demonstrator
app.post('/api/demo/hash-test', async (req, res, next) => {
  try {
    const plainText = String(req.body.password || 'SecurePassword123!').slice(0, 100);
    const startTime = Date.now();
    const hash = await bcrypt.hash(plainText, 12);
    const durationMs = Date.now() - startTime;

    res.json({
      plainText,
      algorithm: 'bcrypt (Blowfish cipher)',
      costFactor: 12,
      saltRounds: 12,
      durationMs,
      generatedHash: hash,
      breakdown: {
        prefix: hash.substring(0, 4), // e.g. $2a$
        cost: hash.substring(4, 6),   // 12
        salt: hash.substring(7, 29),  // 22 chars of salt
        ciphertext: hash.substring(29) // 31 chars of ciphertext
      }
    });
  } catch (err) {
    next(err);
  }
});

// Fallback to index.html for SPA client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';

  if (status === 500) {
    console.error('Unhandled server error:', err);
  }

  res.status(status).json({
    error: message
  });
});

// Start Server if run directly
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(`🔒 Secure Login System Server running!`);
    console.log(`🌐 Local URL: http://localhost:${PORT}`);
    console.log(`🛡️  Security Features Active:`);
    console.log(`   ✓ Passwords: bcrypt (12 rounds)`);
    console.log(`   ✓ SQL Injection: Parameterized Statements`);
    console.log(`   ✓ Sessions: HttpOnly, SameSite=Lax, Fixation Protected`);
    console.log(`   ✓ Headers: Helmet CSP, HSTS, X-Frame-Options`);
    console.log(`   ✓ Rate Limiting: Active on Auth & 2FA`);
    console.log(`   ✓ Two-Factor Auth: RFC 6238 TOTP with QR Code`);
    console.log(`=================================================`);
  });
}

module.exports = app;
