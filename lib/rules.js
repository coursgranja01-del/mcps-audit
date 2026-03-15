'use strict';

/**
 * Embedded security rules — OWASP Agentic AI Top 10 + MCP Top 10
 * Ported from AgentSign Registry rules.json v1.1.0
 */

const RULES = {
  version: '1.1.0',
  updated_at: '2026-03-13T00:00:00Z',
  source: 'AgentSign Security Research + OWASP Agentic AI Top 10 (2025) + MITRE ATT&CK + STRIDE',
  rules: [
    {
      id: 'AS-001',
      owasp: 'AA-03',
      attack: 'T1059',
      stride: 'Elevation of Privilege',
      severity: 'CRITICAL',
      check: 'unsafe_execution',
      patterns: [
        '\\bexec\\s*\\(',
        '\\beval\\s*\\(',
        'subprocess.*shell\\s*=\\s*True',
        '\\bos\\.system\\s*\\(',
        '\\b__import__\\s*\\(',
        'child_process',
        '\\bFunction\\s*\\(',
        'pickle\\.loads?\\s*\\('
      ],
      description: 'Dangerous code execution patterns that allow arbitrary command injection',
      runbook: '1. Replace exec()/eval() with AST-parsed execution (ast.literal_eval for data, RestrictedPython for code). 2. Run agent code in Docker/gVisor sandbox with --no-new-privileges. 3. Use allowlist of permitted modules via importlib. 4. Add mandatory human confirmation before shell commands.'
    },
    {
      id: 'AS-002',
      owasp: 'AA-05',
      attack: 'T1552',
      stride: 'Information Disclosure',
      severity: 'HIGH',
      check: 'secret_scan',
      patterns: [
        '[\'"][A-Za-z0-9]{32,}[\'"]',
        'password\\s*=\\s*[\'"][^\'"]+[\'"]',
        '(?:api[_-]?key|secret|token)\\s*[:=]\\s*[\'"][^\'"]{8,}[\'"]',
        'AKIA[0-9A-Z]{16}',
        'sk-[a-zA-Z0-9]{20,}',
        'ghp_[a-zA-Z0-9]{36}'
      ],
      exclude_context: ['hash', 'signature', 'agent_id'],
      description: 'Hardcoded secrets, API keys, tokens, or credentials in source code',
      runbook: '1. Move all secrets to environment variables or a vault (HashiCorp Vault, AWS Secrets Manager, dotenv). 2. Add pre-commit hooks (detect-secrets, trufflehog) to block secret commits. 3. Rotate any exposed keys immediately. 4. Add .env to .gitignore.'
    },
    {
      id: 'AS-003',
      owasp: 'AA-04',
      attack: 'T1078',
      stride: 'Elevation of Privilege',
      severity: 'MEDIUM',
      check: 'excessive_permissions',
      permission_flags: ['admin', 'delete', 'execute'],
      patterns: ['\\badmin\\b', '\\bdelete\\b', '\\bexecute\\b', 'permission.*admin', 'role.*admin', 'grant.*all'],
      description: 'Agent requests high-risk permissions beyond minimum necessary',
      runbook: '1. Apply principle of least privilege — grant only permissions the agent needs for its specific task. 2. Use scoped API tokens (read-only where possible). 3. Implement permission escalation flow requiring human approval. 4. Audit permission usage and revoke unused grants.'
    },
    {
      id: 'AS-004',
      owasp: 'AA-02',
      attack: 'T1190',
      stride: 'Tampering',
      severity: 'HIGH',
      check: 'prompt_injection',
      patterns: ['open\\s*\\('],
      context_required: ['prompt', 'instruction', 'system'],
      description: 'File input flows near prompt or instruction handling create injection vectors',
      runbook: '1. Sanitize all file contents before injecting into prompts (strip control chars, limit length). 2. Use structured input schemas — never concatenate raw file content into system prompts. 3. Implement input/output firewalls (Rebuff, LLM Guard). 4. Separate data plane from control plane in prompt construction.'
    },
    {
      id: 'AS-005',
      owasp: 'AA-02',
      attack: 'T1055',
      stride: 'Tampering',
      severity: 'CRITICAL',
      check: 'injection_pattern',
      patterns: [
        'ignore\\s+(previous|all|above)\\s+(instructions|prompts)',
        'system\\s*:\\s*',
        ';\\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\\s',
        '<script[\\s>]',
        '\\b(rm\\s+-rf|sudo|chmod\\s+777)\\b'
      ],
      description: 'Known prompt injection, SQL injection, XSS, or command injection patterns',
      runbook: '1. Validate and sanitize all inputs with strict allowlists. 2. Use parameterized queries for any database access (never string concatenation). 3. HTML-encode all agent output before rendering. 4. Implement content security policy (CSP) headers. 5. Block known injection patterns at the input boundary.'
    },
    {
      id: 'AS-006',
      owasp: 'AA-09',
      attack: 'T1610',
      stride: 'Elevation of Privilege',
      severity: 'HIGH',
      check: 'sandboxing',
      sandbox_indicators: ['sandbox', 'docker', 'container', 'isolat', 'jail', 'chroot', 'seccomp', 'namespace'],
      description: 'Code execution without sandboxing or isolation mechanisms',
      runbook: '1. Run all agent-generated code in Docker containers with --network=none and read-only filesystem. 2. Use gVisor/Firecracker for stronger isolation. 3. Set resource limits (CPU, memory, time) on execution. 4. Use E2B or Modal for managed sandboxed execution. 5. Never execute agent code in the host process.'
    },
    {
      id: 'AS-007',
      owasp: 'AA-06',
      attack: 'T1195',
      stride: 'Tampering',
      severity: 'LOW',
      check: 'supply_chain',
      patterns: ['pip install', 'npm install', 'require\\s*\\(', 'import\\s+\\w+\\s+from'],
      mitigations: ['integrity', 'hash', 'checksum', 'lock'],
      description: 'External dependencies without integrity verification or lockfiles',
      runbook: '1. Use lockfiles (package-lock.json, poetry.lock, requirements.txt with hashes). 2. Pin exact dependency versions — never use >= or latest. 3. Run npm audit / pip-audit in CI. 4. Use pip install --require-hashes for Python. 5. Verify package signatures where available.'
    },
    {
      id: 'AS-008',
      owasp: 'AA-01',
      attack: 'T1548',
      stride: 'Elevation of Privilege',
      severity: 'HIGH',
      check: 'excessive_agency',
      patterns: ['tool_choice.*auto', 'allow_dangerous_request', 'auto_approve', 'bypass.*safety', 'skip.*confirm'],
      description: 'Agent configured with unrestricted tool access or auto-approval of dangerous actions',
      runbook: '1. Implement mandatory human-in-the-loop for destructive operations (delete, write, execute, send). 2. Use tool_choice=\'none\' or explicit tool allowlists instead of \'auto\'. 3. Add confirmation prompts before irreversible actions. 4. Log all tool invocations with full parameters for audit.'
    },
    {
      id: 'AS-009',
      owasp: 'AA-07',
      attack: 'T1059.007',
      stride: 'Tampering',
      severity: 'MEDIUM',
      check: 'output_handling',
      patterns: ['innerHTML\\s*=', 'document\\.write\\s*\\(', 'dangerouslySetInnerHTML', '\\.html\\s*\\('],
      description: 'Unsafe output handling that could enable XSS through agent-generated content',
      runbook: '1. Always use textContent instead of innerHTML for agent-generated text. 2. Use DOMPurify or sanitize-html before rendering any HTML from agents. 3. Implement Content Security Policy (CSP) headers. 4. Use React\'s default escaping (avoid dangerouslySetInnerHTML). 5. Validate and escape all agent output at the rendering boundary.'
    },
    {
      id: 'AS-010',
      owasp: 'AA-08',
      attack: 'T1562.002',
      stride: 'Repudiation',
      severity: 'MEDIUM',
      check: 'logging_monitoring',
      negative_check: true,
      indicators: ['logger', 'logging', 'audit', 'telemetry', 'monitor', 'console\\.log', 'winston', 'pino', 'bunyan'],
      description: 'No evidence of logging, auditing, or monitoring in agent code',
      runbook: '1. Add structured logging (JSON) for every agent action, tool call, and decision. 2. Include agent_id, timestamp, action, parameters, and outcome in each log entry. 3. Ship logs to a centralized SIEM (Splunk, Elastic, Sentinel). 4. Set up alerts for anomalous patterns (high-frequency tool calls, unusual commands). 5. Retain logs for compliance (90 days minimum).'
    },
    {
      id: 'AS-011',
      owasp: 'AA-10',
      attack: 'T1041',
      stride: 'Information Disclosure',
      severity: 'HIGH',
      check: 'data_exfiltration',
      patterns: ['fetch\\s*\\(.*\\+', 'axios\\.(post|put)\\s*\\(.*\\+', 'requests\\.(post|put)\\s*\\(.*\\+', 'urllib', 'http\\.request'],
      context_required: ['user', 'data', 'secret', 'credential', 'token'],
      description: 'Dynamic HTTP requests that could exfiltrate sensitive data to attacker-controlled endpoints',
      runbook: '1. Implement URL allowlisting — agents can only make HTTP requests to pre-approved domains. 2. Use egress firewalls or network policies to restrict outbound traffic. 3. Redact sensitive data (tokens, credentials) before passing to agent context. 4. Log all outbound HTTP requests with destination and payload size. 5. Block requests containing sensitive patterns in the body.'
    },
    {
      id: 'AS-012',
      owasp: 'MCP-07',
      attack: 'T1078.004',
      stride: 'Spoofing',
      severity: 'HIGH',
      check: 'mcp_no_auth',
      patterns: ['createServer\\s*\\(', 'app\\.listen\\s*\\(', 'serve\\s*\\('],
      mitigations: ['authenticate', 'authorization', 'bearer\\s', 'middleware.*auth', 'jwt\\.verify', 'oauth', 'verifyToken', 'requireAuth'],
      description: 'MCP server or agent endpoint without authentication mechanism',
      runbook: '1. Add authentication middleware (JWT, API key, or OAuth2) to all agent/MCP endpoints. 2. Use mTLS for server-to-server agent communication. 3. Implement rate limiting per authenticated client. 4. Validate agent identity with signed passports (AgentSign). 5. Never expose agent endpoints on 0.0.0.0 without auth.'
    }
  ]
};

module.exports = RULES;
