'use strict';

const path = require('path');
const { collectFiles } = require('./collector');
const { scanAll } = require('./scanner');
const { analyzeMCP } = require('./owasp-mcp');
const RULES = require('./rules');

const SCORE_MAP = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3 };

function buildReport(targetPath, options = {}) {
  const resolvedPath = path.resolve(targetPath);
  const files = collectFiles(resolvedPath);

  // Scan: Agentic AI rules
  const allFindings = scanAll(files);

  // Filter by severity
  const sevOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const minIdx = sevOrder.indexOf((options.severity || 'LOW').toUpperCase());
  const findings = allFindings.filter(f => sevOrder.indexOf(f.severity) >= minIdx);

  // MCP Top 10 analysis
  const mcpAnalysis = analyzeMCP(files);

  // Score calculation
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => counts[f.severity]++);
  const riskScore = Math.min(100, findings.reduce((s, f) => s + (SCORE_MAP[f.severity] || 0), 0));

  // Verdict
  let verdict;
  if (counts.CRITICAL > 0) verdict = 'FAIL';
  else if (counts.HIGH >= 1) verdict = 'WARN';
  else verdict = 'PASS';

  // Mitigated score: remove findings that MCPS can address
  const mcpsRules = new Set(['AS-006', 'AS-008', 'AS-012']);
  const mitigatedFindings = findings.filter(f => !mcpsRules.has(f.rule));
  const mitigatedScore = Math.min(100, mitigatedFindings.reduce((s, f) => s + (SCORE_MAP[f.severity] || 0), 0));

  // Reduction
  const reduction = riskScore > 0 ? Math.round((1 - mitigatedScore / riskScore) * 100) : 0;

  // Languages scanned
  const languages = {};
  files.forEach(f => { languages[f.language] = (languages[f.language] || 0) + 1; });

  const totalLines = files.reduce((s, f) => s + f.content.split('\n').length, 0);

  const reportId = 'MCPS-' + Date.now().toString(36).toUpperCase();

  return {
    report_id: reportId,
    target: resolvedPath,
    name: options.name || path.basename(resolvedPath),
    scanned_at: new Date().toISOString(),
    scanner_version: '1.0.0',
    rules_version: RULES.version,
    scope: {
      files: files.length,
      lines: totalLines,
      languages,
      max_files: 500,
      max_file_size: '500KB'
    },
    verdict,
    risk_score: riskScore,
    mitigated_score: mitigatedScore,
    risk_reduction: reduction,
    severity_counts: counts,
    total_findings: findings.length,
    findings,
    mcp_analysis: mcpAnalysis,
    mcps_detected: mcpAnalysis.mcps_detected
  };
}

module.exports = { buildReport };
