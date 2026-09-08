/**
 * Secure Login System - Frontend Client Application
 * Handles authentication, 2FA workflows, password strength evaluation,
 * and security lab demonstrations.
 */

// Application State
const state = {
  currentUser: null,
  activeView: 'login-view'
};

// DOM Elements
const views = {
  login: document.getElementById('login-view'),
  register: document.getElementById('register-view'),
  dashboard: document.getElementById('dashboard-view'),
  lab: document.getElementById('lab-view')
};

const navBtns = {
  login: document.getElementById('nav-login-btn'),
  register: document.getElementById('nav-register-btn'),
  dashboard: document.getElementById('nav-dashboard-btn'),
  lab: document.getElementById('nav-lab-btn'),
  logout: document.getElementById('logout-btn')
};

const userBadge = document.getElementById('nav-user-badge');
const usernameDisplay = document.getElementById('nav-username-display');
const twoFactorModal = document.getElementById('twofactor-modal');

// -------------------------------------------------------------
// Toast Notification Helper
// -------------------------------------------------------------
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icon = type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ';
  toast.innerHTML = `<span style="font-weight: bold;">${icon}</span> <span>${escapeHtml(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(50px)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// -------------------------------------------------------------
// View Switching Logic
// -------------------------------------------------------------
function switchView(viewId) {
  state.activeView = viewId;

  // Hide all views
  Object.values(views).forEach(view => {
    if (view) view.style.display = 'none';
  });

  // Show selected view
  const targetView = document.getElementById(viewId);
  if (targetView) {
    targetView.style.display = (viewId === 'dashboard-view' || viewId === 'lab-view') ? 'flex' : 'flex';
  }

  // Update nav buttons
  Object.values(navBtns).forEach(btn => {
    if (btn) btn.classList.remove('active');
  });

  const activeBtn = document.querySelector(`.nav-btn[data-view="${viewId}"]`);
  if (activeBtn) activeBtn.classList.add('active');
}

// Attach Nav Clicks
document.querySelectorAll('.nav-btn').forEach(btn => {
  btn.addEventListener('click', (e) => {
    const viewId = e.currentTarget.dataset.view;
    if (viewId) switchView(viewId);
  });
});

document.getElementById('switch-to-register').addEventListener('click', (e) => {
  e.preventDefault();
  switchView('register-view');
});

document.getElementById('switch-to-login').addEventListener('click', (e) => {
  e.preventDefault();
  switchView('login-view');
});

// Password Toggle (Show/Hide)
document.querySelectorAll('.password-toggle').forEach(toggleBtn => {
  toggleBtn.addEventListener('click', () => {
    const inputId = toggleBtn.dataset.target;
    const input = document.getElementById(inputId);
    if (!input) return;

    if (input.type === 'password') {
      input.type = 'text';
      toggleBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
    } else {
      input.type = 'password';
      toggleBtn.innerHTML = `<svg class="eye-open" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    }
  });
});

// -------------------------------------------------------------
// Real-Time Password Strength Meter
// -------------------------------------------------------------
const regPasswordInput = document.getElementById('reg-password');
const regConfirmPasswordInput = document.getElementById('reg-confirm-password');
const strengthFill = document.getElementById('strength-fill');
const strengthText = document.getElementById('strength-text');

const reqLength = document.getElementById('req-length');
const reqLower = document.getElementById('req-lower');
const reqUpper = document.getElementById('req-upper');
const reqNumber = document.getElementById('req-number');
const reqSpecial = document.getElementById('req-special');
const matchFeedback = document.getElementById('password-match-feedback');

function evaluatePassword(password) {
  let score = 0;

  // Rule 1: Length >= 8
  const hasLength = password.length >= 8;
  if (hasLength) score += 20;
  updateReqUI(reqLength, hasLength);

  // Rule 2: Lowercase
  const hasLower = /[a-z]/.test(password);
  if (hasLower) score += 20;
  updateReqUI(reqLower, hasLower);

  // Rule 3: Uppercase
  const hasUpper = /[A-Z]/.test(password);
  if (hasUpper) score += 20;
  updateReqUI(reqUpper, hasUpper);

  // Rule 4: Number
  const hasNumber = /[0-9]/.test(password);
  if (hasNumber) score += 20;
  updateReqUI(reqNumber, hasNumber);

  // Rule 5: Special Symbol
  const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(password);
  if (hasSpecial) score += 20;
  updateReqUI(reqSpecial, hasSpecial);

  // Update UI bar
  strengthFill.style.width = `${score}%`;

  if (password.length === 0) {
    strengthFill.style.backgroundColor = 'transparent';
    strengthText.textContent = 'Empty';
    strengthText.style.color = 'var(--text-muted)';
  } else if (score < 40) {
    strengthFill.style.backgroundColor = 'var(--danger)';
    strengthText.textContent = 'Weak';
    strengthText.style.color = 'var(--danger)';
  } else if (score < 80) {
    strengthFill.style.backgroundColor = 'var(--warning)';
    strengthText.textContent = 'Medium';
    strengthText.style.color = 'var(--warning)';
  } else if (score === 100) {
    strengthFill.style.backgroundColor = 'var(--success)';
    strengthText.textContent = 'Strong (Secure)';
    strengthText.style.color = 'var(--success)';
  }

  return score === 100;
}

function updateReqUI(el, isMet) {
  if (isMet) {
    el.classList.add('met');
  } else {
    el.classList.remove('met');
  }
}

regPasswordInput.addEventListener('input', (e) => {
  evaluatePassword(e.target.value);
  checkPasswordMatch();
});

regConfirmPasswordInput.addEventListener('input', () => {
  checkPasswordMatch();
});

function checkPasswordMatch() {
  const pwd = regPasswordInput.value;
  const confirm = regConfirmPasswordInput.value;

  if (!confirm) {
    matchFeedback.textContent = '';
    return;
  }

  if (pwd === confirm) {
    matchFeedback.textContent = '✓ Passwords match';
    matchFeedback.style.color = 'var(--success)';
  } else {
    matchFeedback.textContent = '✕ Passwords do not match';
    matchFeedback.style.color = 'var(--danger)';
  }
}

// -------------------------------------------------------------
// Authentication API Handlers
// -------------------------------------------------------------

// 1. Registration Handler
const registerForm = document.getElementById('register-form');
registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const username = document.getElementById('reg-username').value.trim();
  const email = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const confirmPassword = document.getElementById('reg-confirm-password').value;

  if (!username || !email || !password || !confirmPassword) {
    showToast('Please fill out all registration fields.', 'error');
    return;
  }

  if (password !== confirmPassword) {
    showToast('Passwords do not match.', 'error');
    return;
  }

  const submitBtn = document.getElementById('register-submit-btn');
  const btnText = submitBtn.querySelector('.btn-text');
  const spinner = submitBtn.querySelector('.spinner');

  submitBtn.disabled = true;
  btnText.textContent = 'Securing & Registering...';

  try {
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password, confirmPassword })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Failed to register account.');
    }

    showToast(data.message || 'Registration successful!', 'success');
    registerForm.reset();
    evaluatePassword('');

    // Pre-fill username into login form and switch view
    document.getElementById('login-identifier').value = username;
    switchView('login-view');
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    submitBtn.disabled = false;
    btnText.textContent = 'Register Account';
  }
});

// 2. Login Handler
const loginForm = document.getElementById('login-form');
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const identifier = document.getElementById('login-identifier').value.trim();
  const password = document.getElementById('login-password').value;

  if (!identifier || !password) {
    showToast('Please provide your username/email and password.', 'error');
    return;
  }

  const submitBtn = document.getElementById('login-submit-btn');
  const btnText = submitBtn.querySelector('.btn-text');

  submitBtn.disabled = true;
  btnText.textContent = 'Authenticating...';

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier, password })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Invalid credentials.');
    }

    // Check if 2FA is required for this account
    if (data.requires2FA) {
      showToast('Two-Factor Authentication required.', 'info');
      twoFactorModal.style.display = 'flex';
      const otpInput = document.getElementById('twofactor-code-input');
      otpInput.value = '';
      otpInput.focus();
      return;
    }

    // Direct Login Successful
    showToast('Login successful! Welcome back.', 'success');
    loginForm.reset();
    handleAuthSuccess(data.user);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    submitBtn.disabled = false;
    btnText.textContent = 'Sign In Securely';
  }
});

// 3. 2FA Modal Login Challenge Handler
const twoFactorLoginForm = document.getElementById('twofactor-login-form');
twoFactorLoginForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const token = document.getElementById('twofactor-code-input').value.trim();
  if (!token || token.length !== 6) {
    showToast('Please enter a 6-digit TOTP code.', 'error');
    return;
  }

  const submitBtn = document.getElementById('twofactor-submit-btn');
  const btnText = submitBtn.querySelector('.btn-text');

  submitBtn.disabled = true;
  btnText.textContent = 'Verifying 2FA...';

  try {
    const res = await fetch('/api/verify-2fa-login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.error || 'Invalid 2FA code.');
    }

    twoFactorModal.style.display = 'none';
    showToast('2FA Verified! Login successful.', 'success');
    loginForm.reset();
    handleAuthSuccess(data.user);
  } catch (err) {
    showToast(err.message, 'error');
  } finally {
    submitBtn.disabled = false;
    btnText.textContent = 'Verify & Proceed';
  }
});

document.getElementById('twofactor-cancel-btn').addEventListener('click', () => {
  twoFactorModal.style.display = 'none';
  showToast('Login cancelled.', 'warning');
});

// 4. Successful Authentication State Updater
function handleAuthSuccess(user) {
  state.currentUser = user;

  // Update Nav
  navBtns.login.style.display = 'none';
  navBtns.register.style.display = 'none';
  navBtns.dashboard.style.display = 'inline-block';
  navBtns.logout.style.display = 'inline-block';
  userBadge.style.display = 'inline-flex';
  usernameDisplay.textContent = user.username;

  // Update Dashboard View
  document.getElementById('dash-username').textContent = user.username;
  document.getElementById('dash-email').textContent = user.email;
  document.getElementById('dash-avatar').textContent = user.username.charAt(0).toUpperCase();

  const createdDate = user.created_at ? new Date(user.created_at).toLocaleDateString() : 'Today';
  document.getElementById('dash-created').textContent = createdDate;

  update2FAStateUI(user.two_factor_enabled);

  // Load audit logs
  loadSecurityLogs();

  // Switch to Dashboard
  switchView('dashboard-view');
}

// 5. Check Session on Initial Page Load
async function checkAuthStatus() {
  try {
    const res = await fetch('/api/me');
    if (res.ok) {
      const data = await res.json();
      if (data.authenticated && data.user) {
        handleAuthSuccess(data.user);
        return;
      }
    }
  } catch (err) {
    // Unauthenticated
  }

  // Not logged in
  navBtns.login.style.display = 'inline-block';
  navBtns.register.style.display = 'inline-block';
  navBtns.dashboard.style.display = 'none';
  navBtns.logout.style.display = 'none';
  userBadge.style.display = 'none';
  switchView('login-view');
}

// 6. Logout Handler
async function performLogout() {
  try {
    await fetch('/api/logout', { method: 'POST' });
    state.currentUser = null;

    showToast('You have been logged out securely.', 'info');

    navBtns.login.style.display = 'inline-block';
    navBtns.register.style.display = 'inline-block';
    navBtns.dashboard.style.display = 'none';
    navBtns.logout.style.display = 'none';
    userBadge.style.display = 'none';

    switchView('login-view');
  } catch (err) {
    showToast('Error logging out.', 'error');
  }
}

navBtns.logout.addEventListener('click', performLogout);
document.getElementById('dash-logout-btn').addEventListener('click', performLogout);

// -------------------------------------------------------------
// Two-Factor Authentication Management in Dashboard
// -------------------------------------------------------------
const badge2FA = document.getElementById('dash-2fa-badge');
const sec2FADisabled = document.getElementById('section-2fa-disabled');
const sec2FASetup = document.getElementById('section-2fa-setup');
const sec2FAEnabled = document.getElementById('section-2fa-enabled');

function update2FAStateUI(isEnabled) {
  if (isEnabled) {
    badge2FA.textContent = 'Active (Protected)';
    badge2FA.className = 'badge badge-active';
    sec2FADisabled.style.display = 'none';
    sec2FASetup.style.display = 'none';
    sec2FAEnabled.style.display = 'block';
  } else {
    badge2FA.textContent = 'Disabled';
    badge2FA.className = 'badge badge-inactive';
    sec2FADisabled.style.display = 'block';
    sec2FASetup.style.display = 'none';
    sec2FAEnabled.style.display = 'none';
  }
}

// Start 2FA Setup
document.getElementById('btn-start-2fa-setup').addEventListener('click', async () => {
  try {
    const res = await fetch('/api/2fa/generate', { method: 'POST' });
    const data = await res.json();

    if (!res.ok) throw new Error(data.error || 'Failed to initialize 2FA.');

    document.getElementById('qr-code-img').src = data.qrCode;
    document.getElementById('manual-secret-key').textContent = data.secret;

    sec2FADisabled.style.display = 'none';
    sec2FASetup.style.display = 'block';
    document.getElementById('setup-2fa-token').value = '';
    document.getElementById('setup-2fa-token').focus();
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// Cancel 2FA Setup
document.getElementById('btn-cancel-2fa-setup').addEventListener('click', () => {
  sec2FASetup.style.display = 'none';
  sec2FADisabled.style.display = 'block';
});

// Copy Secret Key
document.getElementById('copy-secret-btn').addEventListener('click', () => {
  const secret = document.getElementById('manual-secret-key').textContent;
  navigator.clipboard.writeText(secret).then(() => {
    showToast('2FA Secret copied to clipboard!', 'info');
  });
});

// Confirm & Activate 2FA
document.getElementById('btn-confirm-2fa').addEventListener('click', async () => {
  const token = document.getElementById('setup-2fa-token').value.trim();
  if (!token || token.length !== 6) {
    showToast('Please enter the 6-digit code from your authenticator app.', 'error');
    return;
  }

  try {
    const res = await fetch('/api/2fa/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });

    const data = await res.json();

    if (!res.ok) throw new Error(data.error || 'Invalid 2FA code.');

    showToast(data.message || 'Two-Factor Authentication is now active!', 'success');
    state.currentUser.two_factor_enabled = true;
    update2FAStateUI(true);
    loadSecurityLogs();
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// Disable 2FA
document.getElementById('btn-show-disable-2fa').addEventListener('click', () => {
  const box = document.getElementById('disable-2fa-confirm-box');
  box.style.display = box.style.display === 'none' ? 'block' : 'none';
});

document.getElementById('btn-cancel-disable-2fa').addEventListener('click', () => {
  document.getElementById('disable-2fa-confirm-box').style.display = 'none';
  document.getElementById('disable-2fa-password').value = '';
});

document.getElementById('btn-confirm-disable-2fa').addEventListener('click', async () => {
  const password = document.getElementById('disable-2fa-password').value;
  if (!password) {
    showToast('Password is required to disable 2FA.', 'error');
    return;
  }

  try {
    const res = await fetch('/api/2fa/disable', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });

    const data = await res.json();

    if (!res.ok) throw new Error(data.error || 'Failed to disable 2FA.');

    showToast('2FA has been disabled.', 'warning');
    document.getElementById('disable-2fa-password').value = '';
    document.getElementById('disable-2fa-confirm-box').style.display = 'none';
    state.currentUser.two_factor_enabled = false;
    update2FAStateUI(false);
    loadSecurityLogs();
  } catch (err) {
    showToast(err.message, 'error');
  }
});

// -------------------------------------------------------------
// Security Audit Logs
// -------------------------------------------------------------
async function loadSecurityLogs() {
  const tbody = document.getElementById('audit-log-tbody');
  tbody.innerHTML = '<tr><td colspan="4" class="text-center">Loading audit events...</td></tr>';

  try {
    const res = await fetch('/api/security-logs');
    if (!res.ok) throw new Error('Failed to load logs');

    const data = await res.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="text-center">No security logs recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = logs.map(log => {
      let badgeClass = 'badge-active';
      if (log.event_type.includes('FAILED')) badgeClass = 'badge-danger';
      else if (log.event_type.includes('DISABLED') || log.event_type.includes('CHALLENGE')) badgeClass = 'badge-inactive';

      const formattedDate = new Date(log.created_at).toLocaleString();

      return `
        <tr>
          <td><span class="badge ${badgeClass}">${escapeHtml(log.event_type)}</span></td>
          <td><code>${escapeHtml(log.ip_address)}</code></td>
          <td title="${escapeHtml(log.user_agent)}" style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${escapeHtml(log.user_agent)}
          </td>
          <td>${formattedDate}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-center" style="color: var(--danger);">Failed to retrieve audit log.</td></tr>';
  }
}

document.getElementById('btn-refresh-logs').addEventListener('click', loadSecurityLogs);

// -------------------------------------------------------------
// Interactive Security Lab Handlers
// -------------------------------------------------------------

// 1. SQL Injection Demo
document.querySelectorAll('.sqli-preset-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.getElementById('sqli-test-input').value = btn.dataset.payload;
    runSqliTest();
  });
});

document.getElementById('btn-run-sqli-test').addEventListener('click', runSqliTest);

async function runSqliTest() {
  const input = document.getElementById('sqli-test-input').value;
  const container = document.getElementById('sqli-results-container');

  try {
    const res = await fetch('/api/demo/sqli-test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input })
    });

    const data = await res.json();

    container.style.display = 'grid';

    // Safe Result
    document.getElementById('sqli-safe-explanation').textContent = data.parameterized.explanation;
    document.getElementById('sqli-safe-count').textContent = `${data.parameterized.matchesFound} (Exact literal matches only)`;

    // Vulnerable Result
    document.getElementById('sqli-vuln-sql').innerHTML = `<code>${escapeHtml(data.vulnerable.constructedSql)}</code>`;
    document.getElementById('sqli-vuln-explanation').textContent = data.vulnerable.explanation;
    
    if (data.vulnerable.error) {
      document.getElementById('sqli-vuln-count').innerHTML = `<span style="color:var(--danger)">SQL Syntax Error: ${escapeHtml(data.vulnerable.error)}</span>`;
    } else {
      document.getElementById('sqli-vuln-count').innerHTML = `<span style="color:var(--danger)">${data.vulnerable.matchesFound} users leaked!</span>`;
    }

  } catch (err) {
    showToast('Failed to run SQLi test: ' + err.message, 'error');
  }
}

// 2. BCrypt Password Hashing Inspector
document.getElementById('btn-run-hash-test').addEventListener('click', async () => {
  const password = document.getElementById('hash-test-input').value;
  if (!password) {
    showToast('Please enter a password to hash.', 'warning');
    return;
  }

  const resultsContainer = document.getElementById('hash-results-container');

  try {
    const res = await fetch('/api/demo/hash-test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });

    const data = await res.json();

    resultsContainer.style.display = 'block';
    document.getElementById('full-hash-output').textContent = data.generatedHash;
    document.getElementById('hash-algo').textContent = `${data.breakdown.prefix} (bcrypt Blowfish)`;
    document.getElementById('hash-cost').textContent = `${data.breakdown.cost} (2^${data.breakdown.cost} = 4,096 iterations)`;
    document.getElementById('hash-time').textContent = `${data.durationMs} milliseconds`;
  } catch (err) {
    showToast('Failed to generate hash: ' + err.message, 'error');
  }
});

// Run Initial Check on Page Load
document.addEventListener('DOMContentLoaded', () => {
  checkAuthStatus();
});
