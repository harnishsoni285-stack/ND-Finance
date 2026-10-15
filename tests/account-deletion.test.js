const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const backend = fs.readFileSync(path.join(root, 'NDFinanceBackend', 'Program.cs'), 'utf8');
const frontend = fs.readFileSync(path.join(root, 'index.html'), 'utf8');

test('OWNER-DELETE-01: Account deletion is owner-only and removes the client and linked data atomically', () => {
  const route = backend.match(/app\.MapDelete\("\/api\/auth\/users\/\{username\}"[\s\S]*?\n\}\);/);
  assert.ok(route, 'A client-account deletion endpoint should exist');
  assert.match(route[0], /if \(!actor\.IsOwner\) return Results\.Forbid\(\)/);
  assert.match(route[0], /is_owner = 0/);
  assert.match(route[0], /connection\.BeginTransaction\(\)/);
  assert.match(route[0], /BelongsTo\(loan, targetUsername\)/);
  assert.match(route[0], /DELETE FROM auth_sessions/);
  assert.match(route[0], /DELETE FROM mfa_challenges/);
  assert.match(route[0], /DELETE FROM auth_codes/);
  assert.match(route[0], /DELETE FROM auth_users/);
  assert.match(route[0], /transaction\.Commit\(\)/);
});

test('OWNER-DELETE-02: Owner detail exposes confirmed deletion and overview omits Total Due Assets', () => {
  assert.match(frontend, /window\.confirm\([\s\S]*?Permanently delete client account/);
  assert.match(frontend, /\/api\/auth\/users\/\$\{encodeURIComponent\(user\.username\)\}/);
  assert.doesNotMatch(frontend, /TOTAL DUE ASSETS/);
});
