#!/usr/bin/env node
'use strict';

const path = require('path');
const { buildReport } = require('../lib/reporter');
const { generatePDF } = require('../lib/pdf/generator');

// ANSI colors
const c = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  cyan: '\x1b[36m', white: '\x1b[37m', magenta: '\x1b[35m',
  bgRed: '\x1b[41m', bgGreen: '\x1b[42m', bgYellow: '\x1b[43m'
};

const VERSION = '1.0.0';

function showHelp() {
  console.log(`
${c.cyan}${c.bold}mcps-audit${c.reset} v${VERSION} — OWASP Security Scanner for MCP Servers

${c.bold}USAGE${c.reset}
  mcps-audit [target] [options]

${c.bold}ARGUMENTS${c.reset}
  target          Path to scan (default: current directory)

${c.bold}OPTIONS${c.reset}
  -o, --output    PDF output path (default: ./mcps-audit-report.pdf)
  --name          Agent/server name for report header
  --json          Also output JSON findings to stdout
  --severity      Min severity: LOW|MEDIUM|HIGH|CRITICAL (default: LOW)
  -v, --version   Show version
  -h, --help      Show help

${c.bold}EXAMPLES${c.reset}
  mcps-audit ./my-mcp-server
  mcps-audit ./src --name "My Agent" -o report.pdf
  mcps-audit . --severity HIGH --json

${c.dim}Standards: OWASP MCP Top 10 + OWASP Agentic AI Top 10
Spec: IETF Internet-Draft draft-sharif-mcps-secure-mcp
Powered by AgentSign | agentsign.dev${c.reset}
`);
}

function parseArgs(argv) {
  const args = { target: '.', output: './mcps-audit-report.pdf', name: null, json: false, severity: 'LOW' };
  let i = 2;
  while (i < argv.length) {
    const a = argv[i];
    if (a === '-h' || a === '--help') { showHelp(); process.exit(0); }
    if (a === '-v' || a === '--version') { console.log(VERSION); process.exit(0); }
    if (a === '-o' || a === '--output') { args.output = argv[++i]; i++; continue; }
    if (a === '--name') { args.name = argv[++i]; i++; continue; }
    if (a === '--json') { args.json = true; i++; continue; }
    if (a === '--severity') { args.severity = argv[++i]; i++; continue; }
    if (!a.startsWith('-')) { args.target = a; i++; continue; }
    console.error(`Unknown option: ${a}`);
    process.exit(1);
  }
  return args;
}

function severityColor(sev) {
  const map = { CRITICAL: c.red, HIGH: c.magenta, MEDIUM: c.yellow, LOW: c.cyan };
  return map[sev] || c.white;
}

function statusIcon(status) {
  if (status === 'PASS') return `${c.green}✓${c.reset}`;
  if (status === 'FAIL') return `${c.red}✗${c.reset}`;
  if (status === 'WARN') return `${c.yellow}!${c.reset}`;
  return `${c.dim}-${c.reset}`;
}

function verdictBadge(verdict) {
  if (verdict === 'PASS') return `${c.bgGreen}${c.white}${c.bold} PASS ${c.reset}`;
  if (verdict === 'WARN') return `${c.bgYellow}${c.white}${c.bold} WARN ${c.reset}`;
  return `${c.bgRed}${c.white}${c.bold} FAIL ${c.reset}`;
}

async function main() {
  const args = parseArgs(process.argv);

  console.log(`\n${c.cyan}${c.bold}mcps-audit${c.reset} v${VERSION}\n`);
  console.log(`${c.dim}Scanning: ${path.resolve(args.target)}${c.reset}\n`);

  // Build report
  const report = buildReport(args.target, { name: args.name, severity: args.severity });

  // Terminal output: OWASP MCP Top 10
  console.log(`${c.bold}OWASP MCP Top 10${c.reset}`);
  console.log(`${'─'.repeat(60)}`);
  for (const risk of report.mcp_analysis.risks) {
    const icon = statusIcon(risk.status);
    const pad = risk.id.padEnd(8);
    console.log(`  ${icon} ${pad}${risk.name}`);
  }
  const mcpSum = report.mcp_analysis.summary;
  console.log(`\n  Coverage: ${mcpSum.coverage} mitigated | MCPS SDK: ${report.mcps_detected ? c.green + 'detected' : c.red + 'not found'}${c.reset}\n`);

  // Terminal output: Agentic AI findings
  console.log(`${c.bold}OWASP Agentic AI Findings${c.reset}`);
  console.log(`${'─'.repeat(60)}`);
  const counts = report.severity_counts;
  console.log(`  ${c.red}CRITICAL: ${counts.CRITICAL}${c.reset}  ${c.magenta}HIGH: ${counts.HIGH}${c.reset}  ${c.yellow}MEDIUM: ${counts.MEDIUM}${c.reset}  ${c.cyan}LOW: ${counts.LOW}${c.reset}`);
  console.log();

  // Show top findings
  const top = report.findings.slice(0, 10);
  for (const f of top) {
    const sc = severityColor(f.severity);
    const relPath = path.relative(process.cwd(), f.file);
    console.log(`  ${sc}[${f.severity}]${c.reset} ${f.rule} ${c.dim}${relPath}:${f.line}${c.reset}`);
    console.log(`         ${f.detail}`);
  }
  if (report.findings.length > 10) {
    console.log(`\n  ${c.dim}... and ${report.findings.length - 10} more findings${c.reset}`);
  }

  // Verdict
  console.log(`\n${'─'.repeat(60)}`);
  console.log(`  Verdict: ${verdictBadge(report.verdict)}  Risk Score: ${c.bold}${report.risk_score}/100${c.reset}`);
  if (report.risk_score > report.mitigated_score) {
    console.log(`  With MCPS: ${c.green}${report.mitigated_score}/100${c.reset} (${report.risk_reduction}% reduction)`);
  }
  console.log(`  Files: ${report.scope.files} | Lines: ${report.scope.lines} | Findings: ${report.total_findings}`);
  console.log();

  // Generate PDF
  const outputPath = path.resolve(args.output);
  console.log(`${c.dim}Generating PDF report...${c.reset}`);

  try {
    await generatePDF(report, outputPath);
    console.log(`${c.green}${c.bold}✓${c.reset} Report saved: ${outputPath}\n`);
  } catch (err) {
    console.error(`${c.red}PDF generation failed: ${err.message}${c.reset}`);
    process.exit(1);
  }

  // JSON output
  if (args.json) {
    console.log(JSON.stringify(report, null, 2));
  }

  process.exit(report.verdict === 'FAIL' ? 1 : 0);
}

main().catch(err => {
  console.error(`${c.red}Error: ${err.message}${c.reset}`);
  process.exit(1);
});
