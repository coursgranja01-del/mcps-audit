# mcps-audit

OWASP Security Scanner for MCP Servers. Checks your code against **OWASP MCP Top 10** + **OWASP Agentic AI Top 10** and generates a professional PDF security report.

Built by [AgentSign](https://agentsign.dev).

---

## Quick Start (3 steps)

```bash
# 1. Install it
npm install -g mcps-audit

# 2. Point it at your code
mcps-audit ./my-mcp-server

# 3. Open the PDF report
open mcps-audit-report.pdf
```

That's it. You get:
- A colored terminal summary showing what passed and what failed
- A professional PDF report (saved to `./mcps-audit-report.pdf`)

---

## How It Works (explain like I'm 5)

You have code. You want to know if it's safe.

`mcps-audit` reads your code files (`.js`, `.ts`, `.py`, `.json`), looks for **20 types of security problems**, and tells you:

- **PASS** = You're good. No serious issues found.
- **WARN** = Some problems. You should fix them.
- **FAIL** = Serious problems. Fix these before shipping.

It also shows you exactly **which file, which line**, and **how to fix it**.

The PDF report is designed to hand to your security team, your boss, or your client. It looks professional and covers two major standards:

1. **OWASP MCP Top 10** — Security risks specific to MCP (Model Context Protocol) servers
2. **OWASP Agentic AI Top 10** — Security risks for AI agents in general

---

## Install

**Global (recommended):**
```bash
npm install -g mcps-audit
```

**Local (in your project):**
```bash
npm install --save-dev mcps-audit
npx mcps-audit .
```

**No install (one-off):**
```bash
npx mcps-audit ./my-code
```

Requires Node.js 18+. One dependency (pdfkit for PDF generation). No Chrome, no Puppeteer, no heavy stuff.

---

## Usage

```
mcps-audit [target] [options]
```

| Option | What it does | Default |
|--------|-------------|---------|
| `target` | Folder or file to scan | `.` (current directory) |
| `-o, --output` | Where to save the PDF | `./mcps-audit-report.pdf` |
| `--name` | Name shown in the report | Folder name |
| `--json` | Print JSON findings to terminal | Off |
| `--severity` | Only show this level and above: `LOW` `MEDIUM` `HIGH` `CRITICAL` | `LOW` (show everything) |
| `-v, --version` | Print version | |
| `-h, --help` | Show help | |

### Examples

```bash
# Scan current directory
mcps-audit

# Scan a specific folder, name it in the report
mcps-audit ./src --name "My MCP Server"

# Only care about HIGH and CRITICAL issues
mcps-audit . --severity HIGH

# Save report somewhere specific
mcps-audit ./server -o ~/Desktop/security-report.pdf

# Get machine-readable JSON output
mcps-audit . --json

# Scan a single file
mcps-audit ./server.js
```

### In CI/CD

```yaml
# GitHub Actions
- run: npx mcps-audit . --severity HIGH
  # Exit code 1 if FAIL verdict, 0 if PASS/WARN
```

---

## What It Checks

### OWASP MCP Top 10 (10 risks)

| ID | Risk | What it means |
|----|------|--------------|
| MCP-01 | Rug Pulls | Tool definitions change after you approve them |
| MCP-02 | Tool Poisoning | Hidden instructions in tool descriptions |
| MCP-03 | Privilege Escalation | Combining tools to get more access than intended |
| MCP-04 | Cross-Server Forgery | One MCP server tricks another |
| MCP-05 | Sampling Manipulation | Server manipulates AI responses |
| MCP-06 | Prompt Injection via MCP | Malicious data injected through tool responses |
| MCP-07 | Resource Exhaustion | No auth = anyone can abuse your server |
| MCP-08 | Insufficient Logging | No audit trail for what happened |
| MCP-09 | Insecure MCP-to-MCP | No origin validation between servers |
| MCP-10 | Context Pollution | Malicious data pollutes the shared context |

### OWASP Agentic AI Top 10 (12 rules)

| Rule | Checks for | Severity |
|------|-----------|----------|
| AS-001 | `exec()`, `eval()`, `subprocess` — dangerous code execution | CRITICAL |
| AS-002 | Hardcoded API keys, passwords, tokens | HIGH |
| AS-003 | Excessive permissions (admin, delete, execute) | MEDIUM |
| AS-004 | File input flowing into prompts (injection vector) | HIGH |
| AS-005 | Known injection patterns: SQL, XSS, command injection | CRITICAL |
| AS-006 | Code execution without sandboxing | HIGH |
| AS-007 | Dependencies without lockfile or integrity checks | LOW |
| AS-008 | Auto-approve, bypass safety, skip confirmation | HIGH |
| AS-009 | `innerHTML`, `document.write` — unsafe output | MEDIUM |
| AS-010 | No logging or monitoring detected | MEDIUM |
| AS-011 | HTTP requests that could exfiltrate sensitive data | HIGH |
| AS-012 | Server endpoints without authentication | HIGH |

---

## The PDF Report

The generated report includes these sections:

1. **Cover page** — Shield logo, target name, date, report ID
2. **Executive summary** — PASS/WARN/FAIL verdict, risk score bar, severity counts
3. **Risk comparison** — "WITHOUT MCPS" (red) vs "WITH MCPS" (green) side-by-side
4. **OWASP MCP Top 10 matrix** — Pass/Fail/Warn for each of the 10 risks
5. **Agentic AI matrix** — All 12 rules with MITRE ATT&CK + STRIDE mapping
6. **Detailed findings** — File path, line number, code snippet, how to fix
7. **Remediation checklist** — Prioritized by severity, checkbox format
8. **Methodology** — Standards referenced, scanner version, contact info

Every page has footers. No blank pages. Print-ready A4.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | PASS or WARN verdict |
| `1` | FAIL verdict (CRITICAL findings found) |

Use this in CI to fail builds on critical security issues.

---

## Standards

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10)
- [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10)
- [MCPS IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp)
- [MITRE ATT&CK](https://attack.mitre.org)

## License

MIT
