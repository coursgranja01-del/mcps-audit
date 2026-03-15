'use strict';

const RULES = require('./rules');

/**
 * Scan a single file against all Agentic AI rules.
 * Returns findings with file path and line numbers.
 */
function scanFile(file) {
  const findings = [];
  const lines = file.content.split('\n');
  const rules = RULES.rules;

  // AS-001: Unsafe Execution
  const r001 = rules.find(r => r.id === 'AS-001');
  if (r001) {
    for (let i = 0; i < lines.length; i++) {
      for (const pat of r001.patterns) {
        const rx = new RegExp(pat, 'i');
        if (rx.test(lines[i])) {
          findings.push(makeFinding(r001, file.path, i + 1, lines, i,
            'Dangerous execution: ' + lines[i].trim().slice(0, 80)));
          break;
        }
      }
    }
  }

  // AS-002: Secret Scan
  const r002 = rules.find(r => r.id === 'AS-002');
  if (r002) {
    const excludeRx = r002.exclude_context ? new RegExp(r002.exclude_context.join('|'), 'i') : null;
    for (let i = 0; i < lines.length; i++) {
      if (excludeRx && excludeRx.test(lines[i])) continue;
      for (const pat of r002.patterns) {
        const rx = new RegExp(pat, 'i');
        if (rx.test(lines[i])) {
          let kind = 'possible hardcoded secret';
          if (/AKIA/.test(pat)) kind = 'AWS access key';
          else if (/sk-/.test(pat)) kind = 'OpenAI/Stripe secret key';
          else if (/ghp_/.test(pat)) kind = 'GitHub PAT';
          else if (/password/.test(pat)) kind = 'hardcoded password';
          else if (/api[_-]?key/.test(pat)) kind = 'hardcoded API key';
          findings.push(makeFinding(r002, file.path, i + 1, lines, i,
            'Potential secret: ' + kind));
          break;
        }
      }
    }
  }

  // AS-003: Excessive Permissions
  const r003 = rules.find(r => r.id === 'AS-003');
  if (r003 && r003.patterns) {
    for (let i = 0; i < lines.length; i++) {
      for (const pat of r003.patterns) {
        if (new RegExp(pat, 'i').test(lines[i])) {
          findings.push(makeFinding(r003, file.path, i + 1, lines, i,
            'High-risk permission pattern: ' + lines[i].trim().slice(0, 80)));
          break;
        }
      }
    }
  }

  // AS-004: Prompt Injection via file input
  const r004 = rules.find(r => r.id === 'AS-004');
  if (r004) {
    const hasContext = r004.context_required.some(ctx => new RegExp(ctx, 'i').test(file.content));
    if (hasContext) {
      for (let i = 0; i < lines.length; i++) {
        for (const pat of r004.patterns) {
          if (new RegExp(pat).test(lines[i])) {
            findings.push(makeFinding(r004, file.path, i + 1, lines, i,
              'File input near prompt/instruction handling — injection vector'));
            break;
          }
        }
      }
    }
  }

  // AS-005: Known Injection Patterns
  const r005 = rules.find(r => r.id === 'AS-005');
  if (r005) {
    for (let i = 0; i < lines.length; i++) {
      for (const pat of r005.patterns) {
        if (new RegExp(pat, 'i').test(lines[i])) {
          findings.push(makeFinding(r005, file.path, i + 1, lines, i,
            'Known injection pattern detected'));
          break;
        }
      }
    }
  }

  // AS-006: Sandboxing
  const r006 = rules.find(r => r.id === 'AS-006');
  if (r006) {
    const hasSandbox = r006.sandbox_indicators.some(s => new RegExp(s, 'i').test(file.content));
    if (!hasSandbox) {
      const execRx = /\bexec\s*\(|\beval\s*\(|os\.system\s*\(|subprocess.*shell\s*=\s*True|child_process|new\s+Function\s*\(/i;
      for (let i = 0; i < lines.length; i++) {
        if (execRx.test(lines[i])) {
          findings.push(makeFinding(r006, file.path, i + 1, lines, i,
            'Code execution without sandboxing'));
          break; // one per file
        }
      }
    }
  }

  // AS-007: Supply Chain
  const r007 = rules.find(r => r.id === 'AS-007');
  if (r007) {
    const hasIntegrity = r007.mitigations.some(m => new RegExp(m, 'i').test(file.content));
    if (!hasIntegrity) {
      for (let i = 0; i < lines.length; i++) {
        for (const pat of r007.patterns) {
          if (new RegExp(pat, 'i').test(lines[i])) {
            findings.push(makeFinding(r007, file.path, i + 1, lines, i,
              'Dependency without integrity verification'));
            break;
          }
        }
      }
    }
  }

  // AS-008: Excessive Agency
  const r008 = rules.find(r => r.id === 'AS-008');
  if (r008) {
    for (let i = 0; i < lines.length; i++) {
      for (const pat of r008.patterns) {
        if (new RegExp(pat, 'i').test(lines[i])) {
          findings.push(makeFinding(r008, file.path, i + 1, lines, i,
            'Unrestricted agent autonomy: ' + lines[i].trim().slice(0, 80)));
          break;
        }
      }
    }
  }

  // AS-009: Output Handling
  const r009 = rules.find(r => r.id === 'AS-009');
  if (r009) {
    for (let i = 0; i < lines.length; i++) {
      for (const pat of r009.patterns) {
        if (new RegExp(pat, 'i').test(lines[i])) {
          findings.push(makeFinding(r009, file.path, i + 1, lines, i,
            'Unsafe output handling: ' + lines[i].trim().slice(0, 80)));
          break;
        }
      }
    }
  }

  // AS-010: Logging/Monitoring (negative check)
  const r010 = rules.find(r => r.id === 'AS-010');
  if (r010) {
    const hasLogging = r010.indicators.some(ind => new RegExp(ind, 'i').test(file.content));
    if (!hasLogging && file.language !== 'json') {
      findings.push(makeFinding(r010, file.path, 1, lines, 0,
        'No logging, auditing, or monitoring detected'));
    }
  }

  // AS-011: Data Exfiltration
  const r011 = rules.find(r => r.id === 'AS-011');
  if (r011) {
    const hasSensitive = r011.context_required.some(ctx => new RegExp(ctx, 'i').test(file.content));
    if (hasSensitive) {
      for (let i = 0; i < lines.length; i++) {
        for (const pat of r011.patterns) {
          if (new RegExp(pat, 'i').test(lines[i])) {
            findings.push(makeFinding(r011, file.path, i + 1, lines, i,
              'Dynamic HTTP with sensitive data context'));
            break;
          }
        }
      }
    }
  }

  // AS-012: MCP No Auth
  const r012 = rules.find(r => r.id === 'AS-012');
  if (r012) {
    const hasAuth = r012.mitigations.some(m => new RegExp(m, 'i').test(file.content));
    if (!hasAuth) {
      for (let i = 0; i < lines.length; i++) {
        for (const pat of r012.patterns) {
          if (new RegExp(pat, 'i').test(lines[i])) {
            findings.push(makeFinding(r012, file.path, i + 1, lines, i,
              'Server endpoint without authentication'));
            break;
          }
        }
      }
    }
  }

  return findings;
}

function makeFinding(rule, filePath, line, lines, idx, detail) {
  const start = Math.max(0, idx - 2);
  const end = Math.min(lines.length, idx + 3);
  const snippet = lines.slice(start, end).map((l, i) => {
    const num = start + i + 1;
    const marker = (num === line) ? '>' : ' ';
    return `${marker} ${String(num).padStart(4)} | ${l}`;
  }).join('\n');

  return {
    rule: rule.id,
    check: rule.check,
    severity: rule.severity,
    owasp: rule.owasp,
    attack: rule.attack,
    stride: rule.stride,
    description: rule.description,
    file: filePath,
    line,
    snippet,
    detail,
    runbook: rule.runbook
  };
}

/**
 * Scan all collected files
 */
function scanAll(files) {
  const findings = [];
  for (const file of files) {
    if (file.language === 'json') continue; // skip JSON for code analysis
    findings.push(...scanFile(file));
  }
  return deduplicateFindings(findings);
}

/**
 * Deduplicate: same rule + same file + same line = keep one
 */
function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.rule}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

module.exports = { scanFile, scanAll };
