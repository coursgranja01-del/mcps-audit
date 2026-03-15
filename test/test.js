#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const { collectFiles } = require('../lib/collector');
const { scanAll } = require('../lib/scanner');
const { analyzeMCP } = require('../lib/owasp-mcp');
const { buildReport } = require('../lib/reporter');

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    console.log(`  \x1b[32m✓\x1b[0m ${msg}`);
    passed++;
  } else {
    console.log(`  \x1b[31m✗\x1b[0m ${msg}`);
    failed++;
  }
}

// === Collector Tests ===
console.log('\n\x1b[1mCollector\x1b[0m');
{
  const fixturesDir = path.join(__dirname, 'fixtures');
  const files = collectFiles(fixturesDir);
  assert(files.length >= 2, `Collected ${files.length} fixture files`);
  assert(files.every(f => f.content && f.language && f.path), 'All files have content, language, path');
  assert(files.every(f => f.size > 0), 'All files have size > 0');
  assert(files.some(f => f.language === 'javascript'), 'Found JavaScript files');
}

// === Scanner Tests ===
console.log('\n\x1b[1mScanner (vulnerable fixture)\x1b[0m');
{
  const fixturesDir = path.join(__dirname, 'fixtures');
  const files = collectFiles(fixturesDir);
  const vulnFile = files.find(f => f.path.includes('vulnerable'));
  assert(!!vulnFile, 'Found vulnerable fixture');

  const findings = scanAll([vulnFile]);
  assert(findings.length > 0, `Found ${findings.length} findings in vulnerable server`);

  const rules = findings.map(f => f.rule);
  assert(rules.includes('AS-001'), 'Detected unsafe execution (AS-001)');
  assert(rules.includes('AS-002'), 'Detected hardcoded secrets (AS-002)');
  assert(rules.includes('AS-008'), 'Detected excessive agency (AS-008)');
  assert(rules.includes('AS-012'), 'Detected no-auth server (AS-012)');
  assert(rules.includes('AS-009'), 'Detected unsafe output (AS-009)');

  const criticals = findings.filter(f => f.severity === 'CRITICAL');
  assert(criticals.length > 0, `Found ${criticals.length} CRITICAL findings`);

  // Check finding structure
  const f = findings[0];
  assert(f.file && f.line && f.snippet, 'Finding has file, line, snippet');
  assert(f.runbook && f.runbook.length > 0, 'Finding has runbook');
}

console.log('\n\x1b[1mScanner (secure fixture)\x1b[0m');
{
  const fixturesDir = path.join(__dirname, 'fixtures');
  const files = collectFiles(fixturesDir);
  const secFile = files.find(f => f.path.includes('secure'));
  assert(!!secFile, 'Found secure fixture');

  const findings = scanAll([secFile]);
  const criticals = findings.filter(f => f.severity === 'CRITICAL');
  assert(criticals.length === 0, `No CRITICAL findings in secure server (found ${criticals.length})`);
}

// === MCP Analysis Tests ===
console.log('\n\x1b[1mOWASP MCP Analysis (vulnerable)\x1b[0m');
{
  const fixturesDir = path.join(__dirname, 'fixtures');
  const files = collectFiles(fixturesDir);
  const vulnFile = files.find(f => f.path.includes('vulnerable'));

  const analysis = analyzeMCP([vulnFile]);
  assert(analysis.risks.length === 10, `10 MCP risks analyzed (got ${analysis.risks.length})`);
  assert(!analysis.mcps_detected, 'MCPS not detected in vulnerable server');
  assert(analysis.summary.fail > 0, `Found ${analysis.summary.fail} FAIL risks`);
}

console.log('\n\x1b[1mOWASP MCP Analysis (secure)\x1b[0m');
{
  const fixturesDir = path.join(__dirname, 'fixtures');
  const files = collectFiles(fixturesDir);
  const secFile = files.find(f => f.path.includes('secure'));

  const analysis = analyzeMCP([secFile]);
  assert(analysis.mcps_detected, 'MCPS detected in secure server');
  assert(analysis.summary.pass > 0, `Found ${analysis.summary.pass} PASS risks`);
}

// === Full Report Tests ===
console.log('\n\x1b[1mFull Report (vulnerable)\x1b[0m');
{
  const vulnDir = path.join(__dirname, 'fixtures');
  const report = buildReport(vulnDir, { name: 'Test Vulnerable Server' });

  assert(report.verdict === 'FAIL' || report.verdict === 'WARN', `Verdict: ${report.verdict}`);
  assert(report.risk_score > 0, `Risk score: ${report.risk_score}`);
  assert(report.total_findings > 0, `Total findings: ${report.total_findings}`);
  assert(report.report_id.startsWith('MCPS-'), `Report ID: ${report.report_id}`);
  assert(report.scope.files >= 2, `Files scanned: ${report.scope.files}`);
  assert(report.mcp_analysis.risks.length === 10, 'MCP analysis has 10 risks');

  // Mitigated score should be <= raw score
  assert(report.mitigated_score <= report.risk_score, `Mitigated ${report.mitigated_score} <= raw ${report.risk_score}`);
}

// === PDF Generation Test ===
console.log('\n\x1b[1mPDF Generation\x1b[0m');
{
  const { generatePDF } = require('../lib/pdf/generator');
  const report = buildReport(path.join(__dirname, 'fixtures'), { name: 'PDF Test Server' });
  const outputPath = path.join(__dirname, 'test-report.pdf');

  generatePDF(report, outputPath).then(() => {
    const exists = fs.existsSync(outputPath);
    assert(exists, 'PDF file generated');
    if (exists) {
      const stat = fs.statSync(outputPath);
      assert(stat.size > 1000, `PDF size: ${(stat.size / 1024).toFixed(1)}KB`);
      fs.unlinkSync(outputPath); // cleanup
    }

    // === Summary ===
    console.log(`\n${'─'.repeat(40)}`);
    console.log(`  \x1b[1m${passed} passed\x1b[0m, \x1b[${failed > 0 ? '31' : '32'}m${failed} failed\x1b[0m`);
    console.log();
    process.exit(failed > 0 ? 1 : 0);
  }).catch(err => {
    console.log(`  \x1b[31m✗\x1b[0m PDF generation failed: ${err.message}`);
    failed++;
    console.log(`\n${'─'.repeat(40)}`);
    console.log(`  \x1b[1m${passed} passed\x1b[0m, \x1b[31m${failed} failed\x1b[0m`);
    process.exit(1);
  });
}
