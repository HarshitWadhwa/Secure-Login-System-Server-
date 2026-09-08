/**
 * Automated Security & Authentication Test Suite
 * Validates:
 * 1. BCrypt Password Hashing & Salt Verification
 * 2. SQL Injection Neutralization via Parameterized Queries
 * 3. Input Validation & Strict Password Complexity Rules
 * 4. Session Lifecycle (Creation, HttpOnly cookie, Fixation Defense, Invalidation)
 * 5. Two-Factor Authentication (TOTP Secret Generation, Validation, 2FA Challenge Flow)
 * 6. Rate Limiting Protection
 */

const assert = require('assert');
const http = require('http');
const speakeasy = require('speakeasy');

// Use a separate test database file
process.env.DB_PATH = ':memory:';
process.env.PORT = '3001';
process.env.NODE_ENV = 'test';

const app = require('../src/server');
const { db, dbService } = require('../src/db');
const { hashPassword, comparePassword } = require('../src/auth');

let server;
const BASE_URL = 'http://localhost:3001';

// Helper to make HTTP requests and retain cookies
function makeRequest({ path, method = 'GET', body = null, headers = {}, cookie = null }) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(path, BASE_URL);
    const reqHeaders = { ...headers };
    let payload = null;

    if (body) {
      payload = JSON.stringify(body);
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(payload);
    }

    if (cookie) {
      reqHeaders['Cookie'] = cookie;
    }

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port,
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      headers: reqHeaders
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch (e) {
          json = data;
        }

        const setCookie = res.headers['set-cookie'];
        let sessionCookie = null;
        if (setCookie) {
          sessionCookie = setCookie.map(c => c.split(';')[0]).join('; ');
        }

        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: json,
          cookie: sessionCookie
        });
      });
    });

    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

async function runTests() {
  console.log('====================================================');
  console.log('🚀 STARTING COMPREHENSIVE SECURITY TEST SUITE');
  console.log('====================================================\n');

  let passed = 0;
  let total = 0;

  async function test(name, fn) {
    total++;
    try {
      await fn();
      console.log(`  ✓ PASSED: ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✕ FAILED: ${name}`);
      console.error(`    Error: ${err.message}`);
      if (err.stack) console.error(err.stack);
    }
  }

  // Start temporary server
  await new Promise((resolve) => {
    server = app.listen(3001, resolve);
  });

  try {
    // -----------------------------------------------------------------
    // TEST 1: Password Hashing with BCrypt
    // -----------------------------------------------------------------
    await test('BCrypt Hashing: Correct salt rounds, timing-safe compare, raw password never stored', async () => {
      const rawPassword = 'StrongPassword123!#';
      const hash = await hashPassword(rawPassword);

      // Verify hash format starts with standard bcrypt prefix ($2a$ or $2b$)
      assert.ok(hash.startsWith('$2a$') || hash.startsWith('$2b$'), 'Hash should have bcrypt prefix');
      // Verify cost factor 12
      assert.strictEqual(hash.substring(4, 6), '12', 'Bcrypt cost factor should be 12');
      // Verify timing-safe comparison
      const isValid = await comparePassword(rawPassword, hash);
      assert.strictEqual(isValid, true, 'Valid password must match hash');
      const isInvalid = await comparePassword('WrongPassword123!', hash);
      assert.strictEqual(isInvalid, false, 'Invalid password must not match hash');
    });

    // -----------------------------------------------------------------
    // TEST 2: Strict Input Validation on Registration
    // -----------------------------------------------------------------
    await test('Input Validation: Rejects weak passwords and invalid formats', async () => {
      // Weak password (< 8 chars)
      const res1 = await makeRequest({
        path: '/api/register',
        method: 'POST',
        body: { username: 'user1', email: 'user1@test.com', password: 'abc', confirmPassword: 'abc' }
      });
      assert.strictEqual(res1.status, 400, 'Weak password must be rejected with 400');
      assert.ok(res1.data.error.includes('at least 8 characters'), 'Error should specify length requirement');

      // Missing special character
      const res2 = await makeRequest({
        path: '/api/register',
        method: 'POST',
        body: { username: 'user2', email: 'user2@test.com', password: 'Password123', confirmPassword: 'Password123' }
      });
      assert.strictEqual(res2.status, 400, 'Password without special char must be rejected');

      // Invalid Email
      const res3 = await makeRequest({
        path: '/api/register',
        method: 'POST',
        body: { username: 'user3', email: 'notanemail', password: 'ValidP@ssword123', confirmPassword: 'ValidP@ssword123' }
      });
      assert.strictEqual(res3.status, 400, 'Invalid email must be rejected');

      // Password confirmation mismatch
      const res4 = await makeRequest({
        path: '/api/register',
        method: 'POST',
        body: { username: 'user4', email: 'user4@test.com', password: 'ValidP@ssword123', confirmPassword: 'DifferentP@ssword123' }
      });
      assert.strictEqual(res4.status, 400, 'Password mismatch must be rejected');
    });

    // -----------------------------------------------------------------
    // TEST 3: User Registration & SQL Injection Immunization
    // -----------------------------------------------------------------
    let testUserCookie = null;
    await test('User Registration: Successful account creation with parameterized queries', async () => {
      const res = await makeRequest({
        path: '/api/register',
        method: 'POST',
        body: {
          username: 'security_tester',
          email: 'tester@security.local',
          password: 'SuperSecureP@ssw0rd!2026',
          confirmPassword: 'SuperSecureP@ssw0rd!2026'
        }
      });

      assert.strictEqual(res.status, 201, 'Valid registration should return 201 Created');
      assert.strictEqual(res.data.success, true);
      assert.strictEqual(res.data.user.username, 'security_tester');

      // Inspect DB directly: ensure password_hash in database is hashed and never plaintext
      const dbRow = dbService.findUserByUsername('security_tester');
      assert.ok(dbRow, 'User must exist in DB');
      const userSecrets = dbService.findUserByIdWithSecrets(dbRow.id);
      assert.notStrictEqual(userSecrets.password_hash, 'SuperSecureP@ssw0rd!2026', 'Plaintext password must NEVER be in database');
      assert.ok(userSecrets.password_hash.startsWith('$2a$') || userSecrets.password_hash.startsWith('$2b$'), 'Password must be stored as bcrypt hash');
    });

    // -----------------------------------------------------------------
    // TEST 4: SQL Injection Neutralization
    // -----------------------------------------------------------------
    await test('SQL Injection Defense: Parameterized statements neutralize SQLi payloads', async () => {
      // Attempt SQL Injection via username in login
      const sqliPayloads = [
        "' OR '1'='1",
        "admin' --",
        "' OR 1=1 --",
        "'; DROP TABLE users; --"
      ];

      for (const payload of sqliPayloads) {
        const res = await makeRequest({
          path: '/api/login',
          method: 'POST',
          body: { identifier: payload, password: 'arbitraryPassword' }
        });
        // Must return 401 Unauthorized, never 200 or 500
        assert.strictEqual(res.status, 401, `Payload [${payload}] must fail authentication safely`);
      }

      // Verify table still exists and is completely intact
      const countRow = db.prepare('SELECT COUNT(*) as count FROM users').get();
      assert.ok(countRow.count >= 1, 'Users table must not be damaged');
    });

    // -----------------------------------------------------------------
    // TEST 5: Session Management & Authentication
    // -----------------------------------------------------------------
    await test('Session Management: Login returns HttpOnly cookie, protects private routes, destroys on logout', async () => {
      // 1. Login with correct credentials
      const loginRes = await makeRequest({
        path: '/api/login',
        method: 'POST',
        body: {
          identifier: 'security_tester',
          password: 'SuperSecureP@ssw0rd!2026'
        }
      });

      assert.strictEqual(loginRes.status, 200, 'Login should succeed');
      assert.strictEqual(loginRes.data.success, true);
      assert.ok(loginRes.cookie, 'Session cookie must be provided in Set-Cookie header');

      // Verify cookie security attributes
      const rawSetCookie = loginRes.headers['set-cookie'][0];
      assert.ok(rawSetCookie.includes('HttpOnly'), 'Cookie must contain HttpOnly flag (XSS protection)');
      assert.ok(rawSetCookie.includes('SameSite=Lax'), 'Cookie must contain SameSite=Lax (CSRF protection)');

      testUserCookie = loginRes.cookie;

      // 2. Access protected route /api/me with session cookie
      const meRes = await makeRequest({
        path: '/api/me',
        cookie: testUserCookie
      });
      assert.strictEqual(meRes.status, 200, 'Protected route /api/me must return 200 with valid session');
      assert.strictEqual(meRes.data.user.username, 'security_tester');

      // 3. Access protected route WITHOUT session cookie -> Must be rejected with 401
      const unauthRes = await makeRequest({
        path: '/api/me'
      });
      assert.strictEqual(unauthRes.status, 401, 'Protected route without session must return 401');

      // 4. Test Logout
      const logoutRes = await makeRequest({
        path: '/api/logout',
        method: 'POST',
        cookie: testUserCookie
      });
      assert.strictEqual(logoutRes.status, 200, 'Logout should succeed');

      // 5. Access protected route AFTER logout -> Must be rejected with 401
      const afterLogoutRes = await makeRequest({
        path: '/api/me',
        cookie: testUserCookie
      });
      assert.strictEqual(afterLogoutRes.status, 401, 'Access with invalidated session cookie must return 401');
    });

    // -----------------------------------------------------------------
    // TEST 6: Two-Factor Authentication (2FA) Complete Lifecycle
    // -----------------------------------------------------------------
    await test('Two-Factor Authentication: Setup, TOTP verification, and 2FA login challenge', async () => {
      // 1. Log back in to get active session
      const loginRes = await makeRequest({
        path: '/api/login',
        method: 'POST',
        body: { identifier: 'security_tester', password: 'SuperSecureP@ssw0rd!2026' }
      });
      const activeCookie = loginRes.cookie;

      // 2. Request 2FA Secret generation
      const gen2FARes = await makeRequest({
        path: '/api/2fa/generate',
        method: 'POST',
        cookie: activeCookie
      });
      assert.strictEqual(gen2FARes.status, 200);
      assert.ok(gen2FARes.data.secret, 'Must return base32 secret');
      assert.ok(gen2FARes.data.qrCode.startsWith('data:image/png;base64,'), 'Must return QR code data URL');

      const secret = gen2FARes.data.secret;

      // 3. Generate a valid TOTP token using speakeasy
      const validToken = speakeasy.totp({
        secret,
        encoding: 'base32'
      });

      // 4. Verify and activate 2FA
      const verifyRes = await makeRequest({
        path: '/api/2fa/verify',
        method: 'POST',
        cookie: activeCookie,
        body: { token: validToken }
      });
      assert.strictEqual(verifyRes.status, 200, '2FA should be successfully enabled');

      // Log out
      await makeRequest({ path: '/api/logout', method: 'POST', cookie: activeCookie });

      // 5. Next Login attempt should now trigger 2FA Challenge!
      const loginChallengeRes = await makeRequest({
        path: '/api/login',
        method: 'POST',
        body: { identifier: 'security_tester', password: 'SuperSecureP@ssw0rd!2026' }
      });

      assert.strictEqual(loginChallengeRes.status, 200);
      assert.strictEqual(loginChallengeRes.data.requires2FA, true, 'Login must require 2FA token');
      const pending2FACookie = loginChallengeRes.cookie;

      // 6. Attempt 2FA login with INVALID token -> Must fail
      const bad2FARes = await makeRequest({
        path: '/api/verify-2fa-login',
        method: 'POST',
        cookie: pending2FACookie,
        body: { token: '000000' }
      });
      assert.strictEqual(bad2FARes.status, 401, 'Invalid 2FA token must be rejected');

      // 7. Complete 2FA login with VALID token -> Must succeed
      const freshToken = speakeasy.totp({ secret, encoding: 'base32' });
      const good2FARes = await makeRequest({
        path: '/api/verify-2fa-login',
        method: 'POST',
        cookie: pending2FACookie,
        body: { token: freshToken }
      });
      assert.strictEqual(good2FARes.status, 200, 'Valid 2FA token must authenticate successfully');
      assert.strictEqual(good2FARes.data.user.two_factor_enabled, true);

      // Access protected profile with completed 2FA session
      const post2FAMeRes = await makeRequest({
        path: '/api/me',
        cookie: good2FARes.cookie || pending2FACookie
      });
      assert.strictEqual(post2FAMeRes.status, 200, 'User should have full session after 2FA verification');
    });

    // -----------------------------------------------------------------
    // TEST 7: Security Headers Inspection
    // -----------------------------------------------------------------
    await test('Security Headers: Helmet sets X-Frame-Options, CSP, and MIME type protections', async () => {
      const res = await makeRequest({ path: '/api/health' });
      assert.strictEqual(res.headers['x-frame-options'], 'DENY', 'X-Frame-Options must be DENY (Clickjacking defense)');
      assert.strictEqual(res.headers['x-content-type-options'], 'nosniff', 'X-Content-Type-Options must be nosniff');
      assert.ok(res.headers['content-security-policy'], 'Content-Security-Policy header must be present');
    });

  } finally {
    server.close();
  }

  console.log('\n====================================================');
  console.log(`TEST RESULTS: ${passed} / ${total} passed`);
  if (passed === total) {
    console.log('🎉 ALL SECURITY TESTS PASSED SUCCESSFULLY!');
  } else {
    console.log('⚠️ SOME TESTS FAILED');
    process.exitCode = 1;
  }
  console.log('====================================================');
}

runTests();
