const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const programCsPath = path.resolve(__dirname, '..', 'NDFinanceBackend', 'Program.cs');
const programCsContent = fs.readFileSync(programCsPath, 'utf8');

test('SEC-02: Program.cs merges loans safely when user is Owner instead of blindly overwriting', () => {
  assert.match(
    programCsContent,
    /MergeUserLoansAsync\([^)]*user\.IsOwner[^)]*\)/,
    'MergeUserLoansAsync should handle Owner merges to prevent data loss'
  );
});

test('AUTH-BOOTSTRAP-02: Startup does not seed or overwrite an owner with fixed credentials', () => {
  const bootstrapMatch = programCsContent.match(/static async Task BootstrapOwnerAsync\([\s\S]*?\r?\n}\r?\n\r?\nrecord StorageValue/);
  assert.ok(bootstrapMatch, 'BootstrapOwnerAsync should exist');
  assert.doesNotMatch(bootstrapMatch[0], /defaultOwner|UPDATE auth_users\s+SET password_hash/);
  assert.match(bootstrapMatch[0], /Environment\.GetEnvironmentVariable\("NDF_ADMIN_USERNAME"\)/);
  assert.match(bootstrapMatch[0], /SELECT COUNT\(\*\) FROM auth_users WHERE is_owner = 1/);
});

test('MEMBERSHIP-01: Tier ceilings are saved to profiles and enforced for client loans', () => {
  assert.match(programCsContent, /new MembershipPlan\("Silver", 5_000_000m\)/);
  assert.match(programCsContent, /new MembershipPlan\("Gold", 10_000_000m\)/);
  assert.match(programCsContent, /new MembershipPlan\("Platinum", 30_000_000m\)/);
  assert.match(programCsContent, /new MembershipPlan\("Luxury", null\)/);
  assert.match(programCsContent, /if \(!actor\.IsOwner\) return Results\.Forbid\(\)/);
  assert.match(programCsContent, /GetMembershipPlan\(body\.Membership\)/);
  assert.match(programCsContent, /profile\.MaxPrincipal is decimal maxPrincipal && activePrincipal > maxPrincipal/);
  assert.match(programCsContent, /Membership = plan\.Name/);
});

test('SEC-13: Account details API no longer returns or writes plaintext passwords', () => {
  const detailsMatch = programCsContent.match(/static async Task<List<object>> GetAllUserDetailsAsync\([\s\S]*?\r?\n}\r?\n/);
  assert.ok(detailsMatch, 'GetAllUserDetailsAsync should exist');
  assert.doesNotMatch(detailsMatch[0], /stored_password|storedPassword/);
  assert.doesNotMatch(programCsContent, /stored_password\s*=/);
  assert.doesNotMatch(programCsContent, /StoredPassword|UpdateStoredPasswordAsync/);
});

test('SEC-03: ReserveLoanIdAsync does not have checked(highestId + 1) integer overflow vulnerability', () => {
  assert.equal(
    programCsContent.includes('checked(highestId + 1)'),
    false,
    'checked(highestId + 1) must be replaced with safe bounds checking'
  );
});

test('SEC-06: CSRF protection validates Referer or X-Requested-With when Origin is absent', () => {
  assert.match(
    programCsContent,
    /X-Requested-With/,
    'CSRF check must verify X-Requested-With when Origin is missing'
  );
});

test('DEV-01: Cross-port API access is limited to loopback origins in development', () => {
  assert.match(programCsContent, /app\.UseCors\("LocalDevelopment"\)/);
  assert.match(programCsContent, /parsedOrigin\.Scheme == Uri\.UriSchemeHttp/);
  assert.match(programCsContent, /parsedOrigin\.IsLoopback/);
  assert.match(programCsContent, /IsLoopbackHost\(context\.Request\.Host\.Host\)/);
});

test('DEV-02: Database directory can be isolated for local testing', () => {
  assert.match(programCsContent, /Environment\.GetEnvironmentVariable\("NDF_DATA_DIR"\)/);
  assert.match(programCsContent, /Environment\.SpecialFolder\.LocalApplicationData/);
});

test('AUTH-EMAIL-01: Registration and sessions do not require email verification', () => {
  assert.equal(programCsContent.includes('verify-email'), false);
  assert.equal(programCsContent.includes('record.EmailVerified'), false);
  assert.equal(programCsContent.includes('u.email_verified = 1'), false);
});

test('AUTH-REG-OWNER-01: Client registration endpoint requires an authenticated owner', () => {
  const registerMatch = programCsContent.match(/app\.MapPost\("\/api\/auth\/register"[\s\S]*?\}\)\.RequireRateLimiting\("auth"\);/);
  assert.ok(registerMatch, 'Client registration endpoint should exist');
  assert.match(registerMatch[0], /var actor = await GetSessionUserAsync\(connectionString, context\)/);
  assert.match(registerMatch[0], /if \(actor is null\) return Results\.Unauthorized\(\)/);
  assert.match(registerMatch[0], /if \(!actor\.IsOwner\) return Results\.Forbid\(\)/);
  assert.ok(
    registerMatch[0].indexOf('if (actor is null)') < registerMatch[0].indexOf('var username ='),
    'Authentication should be checked before registration data is processed'
  );
  assert.ok(
    registerMatch[0].indexOf('if (!actor.IsOwner)') < registerMatch[0].indexOf('INSERT INTO auth_users'),
    'Owner authorization should be checked before inserting an account'
  );
});

test('AUTH-BOOTSTRAP-01: First owner bootstrap is loopback-only, one-time, and hashes its password', () => {
  assert.match(programCsContent, /\/api\/auth\/bootstrap\/status/);
  assert.match(programCsContent, /\/api\/auth\/bootstrap/);
  assert.match(programCsContent, /IsLocalBootstrapRequest\(context\)/);
  assert.match(programCsContent, /WHERE NOT EXISTS \(SELECT 1 FROM auth_users WHERE is_owner = 1\)/);
  assert.match(programCsContent, /AuthSecurity\.HashPassword\(body\.Password\)/);
});

test('AUTH-RESET-LOCAL-01: Local password recovery is loopback-only and restricted to the owner', () => {
  assert.match(programCsContent, /\/api\/auth\/password\/reset-local/);
  assert.match(programCsContent, /if \(!IsLocalBootstrapRequest\(context\)\) return Results\.NotFound\(\)/);
  assert.match(programCsContent, /record is null \|\| !record\.IsOwner/);
  assert.match(programCsContent, /AuthSecurity\.HashPassword\(body\.NewPassword\)/);
  assert.match(programCsContent, /RevokeSessionsAsync\(connectionString, record\.Username\)/);
});
