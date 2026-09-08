# 🔒 Secure Login System

A production-grade, secure authentication web application engineered with defense-in-depth security principles. Built with **Node.js**, **Express**, **node:sqlite**, **bcryptjs**, **express-session**, and **RFC 6238 TOTP Two-Factor Authentication (2FA)**.

---

## 🌟 Key Security Features

### 1. Robust Password Hashing (BCrypt)
- Uses **BCrypt** with **12 salt rounds** (Cost Factor 12, 4,096 iterations).
- Generates a unique, cryptographically random salt per user to completely neutralize rainbow table attacks.
- Plaintext passwords are never stored or printed in logs.
- Timing-safe comparison (`bcrypt.compare`) prevents side-channel timing attacks and user enumeration.

### 2. SQL Injection (SQLi) Immunization
- Powered by Node.js built-in `node:sqlite` (`DatabaseSync`).
- Uses strictly **parameterized prepared statements** (`db.prepare('SELECT ... WHERE username = ?').get(...)`).
- User input is bound as pure literal data values rather than executable SQL code, making SQL injection mathematically impossible.

### 3. Comprehensive Input Validation & Sanitization
- Enforces strict password complexity policies:
  - Minimum 8 characters (up to 128)
  - At least 1 lowercase letter
  - At least 1 uppercase letter
  - At least 1 digit
  - At least 1 special symbol (`!@#$%^&*...`)
- Real-time client-side password strength meter with visual progress and checklist.
- Strict username formatting (alphanumeric, underscores, hyphens, 3-30 chars).
- Email validation using `validator.js`.

### 4. Session Management & Session Fixation Protection
- Server-side cookie sessions powered by `express-session`.
- **`HttpOnly: true`**: Prevents client-side scripts from reading session cookies, thwarting XSS session hijacking.
- **`SameSite: 'lax'`**: Mitigates Cross-Site Request Forgery (CSRF).
- **Session Fixation Defense**: Automatically regenerates the session ID upon user authentication.
- Explicit session destruction and cookie clearing on logout.

### 5. Two-Factor Authentication (TOTP 2FA)
- Implements the RFC 6238 standard compatible with **Google Authenticator**, **Microsoft Authenticator**, and **Authy**.
- User scans a dynamic QR code and confirms with a 6-digit one-time code.
- Multi-step login flow: credentials verified first, followed by a 2FA challenge if active on the account.
- Re-authentication required to disable 2FA.

### 6. Rate Limiting & HTTP Security Headers
- **`express-rate-limit`**: Restricts brute-force login attempts and credential stuffing (max 10 attempts / 15 min per IP).
- **`helmet`**: Configures Content Security Policy (CSP), `X-Frame-Options: DENY` (clickjacking defense), `X-Content-Type-Options: nosniff`, and more.

### 7. Interactive Security Lab & Audit Logging
- Built-in **SQL Injection Defense Lab**: Compare parameterized queries vs. vulnerable dynamic string concatenation side-by-side using attack vectors like `' OR '1'='1`.
- Built-in **BCrypt Visualizer**: Inspect the anatomy of a real bcrypt hash (`$2a$12$...`), work factor, and benchmark hashing execution time.
- **Proactive Security Audit Log**: Live dashboard table tracking user events (`ACCOUNT_CREATED`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `2FA_ENABLED`, etc.) with timestamps and IP addresses.

---

## 🚀 Quick Start Guide

### Prerequisites
- Node.js (v18 or higher recommended, fully compatible with v22+ and v26+)
- npm

### 1. Installation
```bash
npm install
```

### 2. Environment Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
You can customize the `PORT` or `SESSION_SECRET` in `.env`.

### 3. Run the Application
```bash
npm start
```
Open your browser and navigate to:
```
http://localhost:3000
```

### 4. Run Automated Security Test Suite
The project includes a full end-to-end security test suite verifying all cryptographic checks, SQL injection immunity, session lifecycles, and 2FA:
```bash
npm test
```

---

## 📁 Project Architecture

```
├── .env.example            # Environment configuration template
├── .gitignore              # Ignored files (node_modules, sqlite, etc.)
├── package.json            # Project manifest & npm scripts
├── README.md               # Documentation & security architecture
├── src/
│   ├── db.js               # Database schema, prepared queries, and audit logging
│   ├── auth.js             # BCrypt hashing, TOTP 2FA, session regeneration
│   ├── middleware.js       # Rate limiters, session guards, and input validators
│   └── server.js           # Express app, helmet security headers, and routes
├── public/
│   ├── index.html          # Clean, modern single-page authentication UI
│   ├── css/
│   │   └── styles.css      # Dark glassmorphism styling & animations
│   └── js/
│       └── app.js          # Interactive authentication, 2FA, and Security Lab
└── test/
    └── security_test.js    # Comprehensive automated test suite
```

---

## 🧪 Testing Scenarios

1. **User Registration**:
   - Try entering an easy password (e.g. `123456`) and observe the real-time strength meter and rejection feedback.
   - Enter a compliant password (e.g. `Password123!@#`) to register.
2. **Login & Session Verification**:
   - Log in and inspect the cookies in browser developer tools (notice the `HttpOnly` and `SameSite` flags).
3. **Two-Factor Authentication Setup**:
   - Go to Dashboard -> Click "Enable Two-Factor Authentication".
   - Scan the QR code with Google Authenticator or Microsoft Authenticator.
   - Enter the 6-digit code to activate 2FA.
   - Log out, enter your username and password, and observe the seamless 2FA challenge modal.
4. **Interactive Security Lab**:
   - Click "Security Lab" in the top navigation bar.
   - Click `' OR '1'='1` or type any payload to see how parameterized queries treat it strictly as a string literal while vulnerable queries expose records.
   - Test password hashing speed and inspect bcrypt salt breakdown.
