const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const indexHtmlPath = path.resolve(__dirname, '..', 'index.html');
const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

test('DEV-01: Localhost Live Server routes API requests to the backend with session cookies', () => {
  assert.match(indexHtmlContent, /window\.location\.port !== '5080'/);
  assert.match(indexHtmlContent, /baseUrl = `http:\/\/\$\{backendHost\}:5080`/);
  assert.match(indexHtmlContent, /credentials: 'include'/);
  assert.match(indexHtmlContent, /connect-src[^"]*http:\/\/localhost:5080/);
});

test('OWNER-CLIENT-01: Owner overview can create a client account and refresh its user list', () => {
  assert.match(indexHtmlContent, /Create a new client user ID/);
  assert.match(indexHtmlContent, /function openCreateClientModal\(\)/);
  assert.match(indexHtmlContent, /async function createClientAccount\(\)/);
  assert.match(indexHtmlContent, /apiRequest\('\/api\/auth\/register'/);
  assert.match(indexHtmlContent, /state\.users = await apiRequest\('\/api\/auth\/users'\)/);
  assert.match(indexHtmlContent, /function renderCreateClientModal\(\)/);
});

test('AUTH-REG-OWNER-01: Self-registration is removed from login and account creation stays in the owner flow', () => {
  const authStart = indexHtmlContent.indexOf('function renderAuth()');
  const authEnd = indexHtmlContent.indexOf('function renderOwnerBootstrap()', authStart);
  assert.notEqual(authStart, -1, 'renderAuth should exist');
  assert.notEqual(authEnd, -1, 'renderOwnerBootstrap should follow renderAuth');
  const authSource = indexHtmlContent.slice(authStart, authEnd);
  assert.match(authSource, /\$\{renderLoginForm\(\)\}/);
  assert.doesNotMatch(authSource, /Create Account|renderRegisterForm|setAuthTab/);
  assert.doesNotMatch(indexHtmlContent, /function\s+(?:renderRegisterForm|doRegister|setAuthTab)\s*\(/);
  assert.match(indexHtmlContent, /async function createClientAccount\(\)/);
  assert.match(indexHtmlContent, /apiRequest\('\/api\/auth\/register'/);
});

test('OWNER-CLIENT-02: Owner assigns a membership when creating a client', () => {
  assert.match(indexHtmlContent, /<select id="client_membership">/);
  assert.match(indexHtmlContent, /value="Silver">Silver · Up to ₹50 lakh/);
  assert.match(indexHtmlContent, /value="Gold">Gold · Up to ₹1 crore/);
  assert.match(indexHtmlContent, /value="Platinum">Platinum · Up to ₹3 crore/);
  assert.match(indexHtmlContent, /value="Luxury">Luxury · Above ₹3 crore/);
  assert.match(indexHtmlContent, /city, membership \}\)/);
});

test('NEW-LOAN-OPTIONAL-METAL-RATE-01: Loan can be saved without a metal rate', () => {
  const submitStart = indexHtmlContent.indexOf('async function submitNewLoan()');
  const submitEnd = indexHtmlContent.indexOf('\n    function val(id)', submitStart);
  assert.notEqual(submitStart, -1, 'New Loan save handler should exist');
  const submitSource = indexHtmlContent.slice(submitStart, submitEnd);
  assert.match(indexHtmlContent, /Metal Rate[\s\S]{0,100}Optional/);
  assert.doesNotMatch(submitSource, /!metalrate/, 'Metal rate must not be required');
  assert.match(submitSource, /metalrate:\s*metalrate === '' \? null : Number\(metalrate\)/);
});

test('CLIENT-UI-01: Client account detail and New Loan hide the membership principal summary', () => {
  const accountStart = indexHtmlContent.indexOf('function renderOwnerUserDetail(user)');
  const accountEnd = indexHtmlContent.indexOf('function ', accountStart + 10);
  const loanStart = indexHtmlContent.indexOf('function renderNewLoanScreen()');
  const loanEnd = indexHtmlContent.indexOf('async function submitNewLoan()', loanStart);
  assert.notEqual(accountStart, -1, 'Client account detail should exist');
  assert.notEqual(loanStart, -1, 'New Loan screen should exist');

  const accountDetail = indexHtmlContent.slice(accountStart, accountEnd);
  const newLoanScreen = indexHtmlContent.slice(loanStart, loanEnd);
  assert.doesNotMatch(accountDetail, /Subscription Membership|No principal ceiling|Membership.*available/);
  assert.doesNotMatch(newLoanScreen, /Membership|Active principal|No principal ceiling/);
  assert.match(indexHtmlContent, /<th>Membership Limit<\/th>/, 'Owner account list keeps membership management information');
});

test('SEC-13: Owner account views do not display login passwords', () => {
  assert.doesNotMatch(indexHtmlContent, /storedPassword|toggleRevealPassword|Login Password|Permanent Password/);
  assert.match(indexHtmlContent, /Membership Limit/);
  assert.match(indexHtmlContent, /Subscription Membership/);
});

test('SEC-01: No hardcoded localApiRequest mock in index.html', () => {
  assert.equal(
    indexHtmlContent.includes('function localApiRequest'),
    false,
    'localApiRequest should be completely removed from index.html'
  );
});

test('SEC-01: No __FORCE_LOCAL_MODE fallback in index.html', () => {
  assert.equal(
    indexHtmlContent.includes('__FORCE_LOCAL_MODE'),
    false,
    '__FORCE_LOCAL_MODE should be completely removed'
  );
});

test('SEC-01: No hardcoded mock OTP 123456 in index.html', () => {
  assert.equal(
    indexHtmlContent.includes("'123456'"),
    false,
    'Hardcoded mock OTP 123456 should not exist in index.html'
  );
});

test('AUTH-EMAIL-01: Registration does not require email verification', () => {
  assert.equal(indexHtmlContent.includes('sendEmailOtp'), false);
  assert.equal(indexHtmlContent.includes('verifyEmailOtp'), false);
  assert.equal(indexHtmlContent.includes('emailVerified'), false);
  assert.equal(indexHtmlContent.includes('/api/otp/'), false);
});

test('AUTH-BOOTSTRAP-01: First-owner setup is available in the browser without a hardcoded password', () => {
  assert.match(indexHtmlContent, /\/api\/auth\/bootstrap\/status/);
  assert.match(indexHtmlContent, /function renderOwnerBootstrap\(\)/);
  assert.match(indexHtmlContent, /function createFirstOwner\(\)/);
  assert.match(indexHtmlContent, /value="ND_TOP1"/);
  assert.equal(indexHtmlContent.includes('value="ND@TOP"'), false);
});

test('SEC-12: Login does not ship or persist a default password', () => {
  assert.doesNotMatch(indexHtmlContent, /Jay khimaj/);
  assert.doesNotMatch(indexHtmlContent, /localStorage\.setItem\(['"]ndf_saved_(?:credentials|accounts)['"]/);
  assert.match(indexHtmlContent, /function saveUsernameLocally\(username\)/);
  assert.doesNotMatch(indexHtmlContent, /id="li_pass"[^>]*value=/);
});

test('AUTH-BOOTSTRAP-01: First-owner password guidance matches the 12-character server minimum', () => {
  assert.match(indexHtmlContent, /Password \(12 characters minimum\).*id="ob_password"/);
  assert.doesNotMatch(indexHtmlContent, /Password \(08 characters minimum\)/);
});

test('AUTH-RESET-LOCAL-01: Local recovery is available in the browser without embedding a password', () => {
  assert.match(indexHtmlContent, /function openLocalPasswordReset\(\)/);
  assert.match(indexHtmlContent, /function resetLocalOwnerPassword\(\)/);
  assert.match(indexHtmlContent, /\/api\/auth\/password\/reset-local/);
  assert.equal(indexHtmlContent.includes('value="ND@TOP"'), false);
});

test('SEC-01: isOwner() relies on server isOwner claim rather than hardcoded ND@TOP username', () => {
  const isOwnerMatch = indexHtmlContent.match(/function\s+isOwner\s*\([^)]*\)\s*\{([^}]+)\}/);
  assert.ok(isOwnerMatch, 'isOwner function should exist');
  assert.equal(
    isOwnerMatch[1].includes("'ND@TOP'"),
    false,
    'isOwner should not compare against hardcoded ND@TOP'
  );
  assert.match(
    isOwnerMatch[1],
    /isOwner/i,
    'isOwner should check isOwner property on currentUser'
  );
});

test('FILE-01: Opening index.html directly explains how to start the local server', () => {
  assert.match(indexHtmlContent, /window\.location\.protocol === 'file:'/);
  assert.match(indexHtmlContent, /showLocalLaunchInstructions\(\)/);
  assert.match(indexHtmlContent, /start-nd-finance\.bat/);
  assert.match(indexHtmlContent, /http:\/\/localhost:5080/);
  assert.match(indexHtmlContent, /else\s*\{\s*loadAll\(\);/);
});

test('FILE-02: Direct file opening redirects to the backend when it is ready', () => {
  assert.match(indexHtmlContent, /async function openLocalWebsite\(\)/);
  assert.match(indexHtmlContent, /api\/health/);
  assert.match(indexHtmlContent, /window\.location\.replace\(appUrl\)/);
});

test('WEB-03: VS Code starts the local backend when the workspace opens', () => {
  const tasks = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', '.vscode', 'tasks.json'), 'utf8'));
  const webTask = tasks.tasks.find(task => task.label === 'Run ND Finance Web');
  assert.ok(webTask, 'Run ND Finance Web task should exist');
  assert.equal(webTask.isBackground, true);
  assert.equal(webTask.runOptions.runOn, 'folderOpen');
  assert.match(webTask.problemMatcher.background.endsPattern, /localhost:5080/);
});

test('WEB-01: The Windows launchers start the browser-based website', () => {
  const packageJson = JSON.parse(fs.readFileSync(path.resolve(__dirname, '..', 'package.json'), 'utf8'));
  const rootLauncher = fs.readFileSync(path.resolve(__dirname, '..', 'start-nd-finance.bat'), 'utf8');
  const backendLauncher = fs.readFileSync(path.resolve(__dirname, '..', 'NDFinanceBackend', 'start-nd-finance.bat'), 'utf8');

  assert.equal(packageJson.scripts.desktop, undefined);
  assert.equal(packageJson.dependencies, undefined);
  assert.doesNotMatch(JSON.stringify(packageJson), /electron/i);
  assert.match(rootLauncher, /NDFinanceBackend\\start-nd-finance\.bat/i);
  assert.match(backendLauncher, /start "" "%APP_URL%\/"/);
});

test('WEB-02: The frontend does not require a remote animation script', () => {
  assert.doesNotMatch(indexHtmlContent, /cdn\.jsdelivr\.net|window\.Motion|fadeInEl\(|popInEl\(|staggerInEls\(/);
  assert.match(indexHtmlContent, /window\.location\.port !== '5080'/);
  assert.match(indexHtmlContent, /http:\/\/\$\{backendHost\}:5080/);
});
