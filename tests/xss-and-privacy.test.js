const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const indexHtmlPath = path.resolve(__dirname, '..', 'index.html');
const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf8');

test('OWNER-INTEREST-01: Owner summary calculates interest earned this month through loan close dates', () => {
  const calcSource = indexHtmlContent.match(/function calcInterestDetailed\([\s\S]*?(?=\n    function fmtMoney)/);
  const monthlySource = indexHtmlContent.match(/function earnedInterestForMonth\([\s\S]*?(?=\n    function ownerDataIssues)/);
  assert.ok(calcSource, 'Interest calculation helper should exist');
  assert.ok(monthlySource, 'Monthly earned-interest helper should exist');

  const calcInterestDetailed = new Function(`${calcSource[0]}; return calcInterestDetailed;`)();
  const earnedInterestForMonth = new Function(
    'calcInterestDetailed',
    `${monthlySource[0]}; return earnedInterestForMonth;`
  )(calcInterestDetailed);
  const now = new Date(2026, 9, 15, 12);
  const loans = [
    { status: 'active', startDate: '2026-09-01T00:00', amount: 1000, rate: 3.1 },
    { status: 'closed', startDate: '2026-09-01T00:00', closeDate: '2026-10-11T00:00', amount: 1000, rate: 3.1 },
    { status: 'closed', startDate: '2026-09-01T00:00', closeDate: '2026-09-30T00:00', amount: 1000, rate: 3.1 }
  ];

  assert.equal(earnedInterestForMonth(loans, now), 25);
  assert.match(indexHtmlContent, /Monthly Earned Interest \(₹\)/);
  assert.match(indexHtmlContent, /MONTHLY EARNED INTEREST/);
});

test('SEARCH-INTEREST-01: Active loan details in Search History expose a calculation-only interest option', () => {
  const detailStart = indexHtmlContent.indexOf('function renderLoanDetailModal()');
  const detailEnd = indexHtmlContent.indexOf('/* ================= YEARLY DATA ================= */', detailStart);
  assert.notEqual(detailStart, -1, 'Loan detail modal should exist');
  const detailSource = indexHtmlContent.slice(detailStart, detailEnd);
  assert.match(detailSource, /l\.status === 'active'/);
  assert.match(detailSource, /id="close_date"/);
  assert.match(detailSource, /runInterestCalc\('\$\{escapeAttrJs\(l\.id\)\}'\)/);
  assert.match(detailSource, /renderInterestResult\(l, false\)/);
});

test('HARDCOPY-LOGO-01: Hard-copy statement uses the loan client shop logo as a centered watermark', () => {
  const printStart = indexHtmlContent.indexOf('function downloadStatementDocument(id)');
  const printEnd = indexHtmlContent.indexOf('function openStatementDownloadOptions(id)', printStart);
  assert.notEqual(printStart, -1, 'Statement document function should exist');
  const printSource = indexHtmlContent.slice(printStart, printEnd);
  assert.match(printSource, /const loanOwner = l\.owner \|\| l\.createdBy/);
  assert.match(printSource, /state\.users\.find\(user => user\.username === loanOwner\)/);
  assert.match(printSource, /const watermark = logoSrc \? `<img class="logo-watermark"/);
  assert.match(printSource, /opacity:\.08/);
});

test('SEC-05: index.html defines sanitizeImageSrc and escapeAttrJs', () => {
  assert.match(indexHtmlContent, /function\s+sanitizeImageSrc/, 'sanitizeImageSrc must be defined');
  assert.match(indexHtmlContent, /function\s+escapeAttrJs/, 'escapeAttrJs must be defined');
});

test('SEC-05: profile logo uses sanitizeImageSrc instead of raw injection', () => {
  assert.equal(
    indexHtmlContent.includes('src="${s.logo}"'),
    false,
    's.logo must not be interpolated without sanitization'
  );
});

test('SEC-10: index.html defines formatAadhaarMasked and masks Aadhaar displays', () => {
  assert.match(indexHtmlContent, /function\s+formatAadhaarMasked/, 'formatAadhaarMasked must be defined');
  assert.match(indexHtmlContent, /formatAadhaarMasked\(l\.aadhar\)/, 'l.aadhar must be displayed using formatAadhaarMasked');
});

test('SEC-11: loan data is escaped in HTML and inline event-handler contexts', () => {
  assert.doesNotMatch(indexHtmlContent, /\$\{l\.itemCode\}/, 'Item codes must be HTML-escaped');
  assert.doesNotMatch(indexHtmlContent, /\$\{loan\.status\}/, 'Loan statuses must be HTML-escaped');
  assert.doesNotMatch(indexHtmlContent, />\$\{(?:l|loan)\.(?:weight|rate|status)\}/, 'Loan fields rendered as HTML text must be HTML-escaped');
  assert.doesNotMatch(indexHtmlContent, /onclick="[^"]*\$\{(?:l|loan)\.id\}/, 'Loan IDs must be JavaScript-escaped in inline handlers');
  assert.match(indexHtmlContent, /escapeHtml\(l\.itemCode\)/, 'Loan details must HTML-escape item codes');
  assert.match(indexHtmlContent, /escapeAttrJs\(loan\.id\)/, 'Loan list handlers must JavaScript-escape loan IDs');
  assert.match(indexHtmlContent, /\.replace\(\/\\u2028\/g, '\\\\u2028'\)/, 'Inline JavaScript strings must escape Unicode line separators');
});
