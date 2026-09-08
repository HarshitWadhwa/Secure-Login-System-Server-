const { DatabaseSync } = require('node:sqlite');
const os = require('os');
const path = require('path');

const defaultDbPath = process.env.VERCEL
  ? path.join(os.tmpdir(), 'secure-login-system.sqlite')
  : path.join(__dirname, '..', 'database.sqlite');
const dbPath = process.env.DB_PATH || defaultDbPath;

let db;
try {
  db = new DatabaseSync(dbPath);
  db.exec('PRAGMA foreign_keys = ON;');
} catch (err) {
  console.warn(`[SQLite] Could not open database at "${dbPath}" (${err.message}). Falling back to in-memory database for serverless resilience.`);
  db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON;');
}

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    email TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    two_factor_secret TEXT DEFAULT NULL,
    two_factor_enabled INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME DEFAULT NULL
  );

  CREATE TABLE IF NOT EXISTS security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_security_logs_user_id ON security_logs(user_id);
`);

// Prepared statements for maximum performance and SQL Injection prevention
const queries = {
  findUserById: db.prepare(`
    SELECT id, username, email, two_factor_enabled, created_at, last_login 
    FROM users WHERE id = ?
  `),

  findUserByIdWithSecrets: db.prepare(`
    SELECT id, username, email, password_hash, two_factor_secret, two_factor_enabled, created_at, last_login 
    FROM users WHERE id = ?
  `),

  findUserByIdentifier: db.prepare(`
    SELECT id, username, email, password_hash, two_factor_secret, two_factor_enabled, created_at, last_login 
    FROM users WHERE username = ? OR email = ?
  `),

  findUserByEmail: db.prepare(`
    SELECT id, email FROM users WHERE email = ?
  `),

  findUserByUsername: db.prepare(`
    SELECT id, username FROM users WHERE username = ?
  `),

  insertUser: db.prepare(`
    INSERT INTO users (username, email, password_hash) 
    VALUES (?, ?, ?)
  `),

  updateLastLogin: db.prepare(`
    UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
  `),

  update2FASecret: db.prepare(`
    UPDATE users SET two_factor_secret = ? WHERE id = ?
  `),

  enable2FA: db.prepare(`
    UPDATE users SET two_factor_enabled = 1 WHERE id = ?
  `),

  disable2FA: db.prepare(`
    UPDATE users SET two_factor_enabled = 0, two_factor_secret = NULL WHERE id = ?
  `),

  insertSecurityLog: db.prepare(`
    INSERT INTO security_logs (user_id, event_type, ip_address, user_agent)
    VALUES (?, ?, ?, ?)
  `),

  getUserSecurityLogs: db.prepare(`
    SELECT id, event_type, ip_address, user_agent, created_at 
    FROM security_logs 
    WHERE user_id = ? 
    ORDER BY created_at DESC 
    LIMIT ?
  `),

  // For educational demo: safe parameterized query
  demoSafeQuery: db.prepare(`
    SELECT id, username, email, created_at FROM users WHERE username = ?
  `)
};

const dbService = {
  findUserById: (id) => queries.findUserById.get(id),
  findUserByIdWithSecrets: (id) => queries.findUserByIdWithSecrets.get(id),
  findUserByIdentifier: (identifier) => queries.findUserByIdentifier.get(identifier, identifier),
  findUserByEmail: (email) => queries.findUserByEmail.get(email),
  findUserByUsername: (username) => queries.findUserByUsername.get(username),
  
  createUser: (username, email, passwordHash) => {
    const res = queries.insertUser.run(username, email, passwordHash);
    return res.lastInsertRowid;
  },

  updateLastLogin: (userId) => {
    queries.updateLastLogin.run(userId);
  },

  set2FASecret: (userId, secret) => {
    queries.update2FASecret.run(secret, userId);
  },

  enable2FA: (userId) => {
    queries.enable2FA.run(userId);
  },

  disable2FA: (userId) => {
    queries.disable2FA.run(userId);
  },

  logSecurityEvent: (userId, eventType, ipAddress, userAgent) => {
    try {
      queries.insertSecurityLog.run(userId, eventType, ipAddress || 'unknown', (userAgent || 'unknown').substring(0, 200));
    } catch (err) {
      console.error('Failed to log security event:', err);
    }
  },

  getUserSecurityLogs: (userId, limit = 10) => {
    return queries.getUserSecurityLogs.all(userId, limit);
  },

  // Educational Demo: Demonstrates the exact difference between string concatenation vs parameterization
  demoCompareSqli: (input) => {
    // 1. Parameterized / Safe approach:
    // The database engine compiles the SQL command structure first,
    // then binds 'input' as a single literal string data value.
    const safeResults = queries.demoSafeQuery.all(input);

    // 2. Simulated Vulnerable approach (read-only demonstration for security education):
    // Vulnerable dynamic SQL concatenates input directly into the query string.
    let vulnerableResults = [];
    let vulnerableError = null;
    try {
      // In a vulnerable app: `SELECT id, username, email, created_at FROM users WHERE username = '${input}'`
      // We safely demonstrate what happens when quotes break syntax or inject TRUE conditions.
      const simulatedVulnerableSql = `SELECT id, username, email, created_at FROM users WHERE username = '${input}'`;
      // We run via db.prepare to show SQL parser behavior
      vulnerableResults = db.prepare(simulatedVulnerableSql).all();
    } catch (err) {
      vulnerableError = err.message;
    }

    return {
      inputProvided: input,
      parameterized: {
        method: "db.prepare('SELECT ... WHERE username = ?').all(input)",
        explanation: "Input is bound as a pure data value. Quotes and SQL keywords are not evaluated as code.",
        matchesFound: safeResults.length,
        results: safeResults
      },
      vulnerable: {
        constructedSql: `SELECT id, username, email, created_at FROM users WHERE username = '${input}'`,
        explanation: "Raw input is concatenated into SQL statement. Special characters alter query semantics, allowing attackers to dump rows or bypass authentication.",
        error: vulnerableError,
        matchesFound: vulnerableResults ? vulnerableResults.length : 0,
        results: vulnerableResults || []
      }
    };
  }
};

module.exports = {
  db,
  dbService
};
