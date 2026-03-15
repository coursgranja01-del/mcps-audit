'use strict';

/**
 * OWASP MCP Top 10 analysis with MCPS detection and coverage mapping.
 */

const MCP_RISKS = [
  {
    id: 'MCP-01',
    name: 'Rug Pulls',
    description: 'Tool definitions change after initial approval, allowing post-install behavior changes',
    vulnerable_patterns: ['bearer.*token', 'api_key.*header', 'authorization.*header', 'tools/list', 'tool.*definition'],
    mcps_patterns: ['createPassport', 'passport_id', 'signPassport', 'verifyPassport'],
    mcps_fix: 'Passport identity binding — tools are tied to verified agent identity',
    mcps_api: 'createPassport(), signPassport()'
  },
  {
    id: 'MCP-02',
    name: 'Tool Poisoning',
    description: 'Malicious instructions hidden in tool descriptions that manipulate LLM behavior',
    vulnerable_patterns: [],
    mcps_patterns: [],
    mcps_fix: 'N/A — requires LLM-level defense',
    mcps_api: 'N/A',
    na: true
  },
  {
    id: 'MCP-03',
    name: 'Privilege Escalation via Tool Composition',
    description: 'Combining low-privilege tools to achieve unauthorized high-privilege operations',
    vulnerable_patterns: ['tools/list', 'tool.*definition', 'listTools', 'callTool'],
    mcps_patterns: ['signTool', 'verifyTool', 'tool_hash'],
    mcps_fix: 'Tool integrity signing — each tool definition is cryptographically signed',
    mcps_api: 'signTool(), verifyTool()'
  },
  {
    id: 'MCP-04',
    name: 'Cross-Server Request Forgery',
    description: 'Untrusted MCP server manipulates a trusted server via shared client context',
    vulnerable_patterns: ['require\\s*\\(', 'import\\s+', 'npm install', 'pip install'],
    mcps_patterns: ['signTool', 'tool_hash', 'verifyTool'],
    mcps_fix: 'Signed tool definitions prevent tampering during cross-server calls',
    mcps_api: 'signTool(), tool_hash'
  },
  {
    id: 'MCP-05',
    name: 'Sampling Manipulation',
    description: 'Server manipulates AI sampling requests to influence client LLM outputs',
    vulnerable_patterns: [],
    mcps_patterns: [],
    mcps_fix: 'N/A — requires client-level defense',
    mcps_api: 'N/A',
    na: true
  },
  {
    id: 'MCP-06',
    name: 'Indirect Prompt Injection via MCP',
    description: 'Attacker injects malicious prompts through data returned by MCP tools',
    vulnerable_patterns: ['jsonrpc', 'method.*call', 'handleRequest', 'processMessage'],
    mcps_patterns: ['signMessage', 'verifyMessage', 'envelope'],
    mcps_fix: 'Signed message envelopes — all MCP messages carry cryptographic signatures',
    mcps_api: 'signMessage(), verifyMessage()'
  },
  {
    id: 'MCP-07',
    name: 'Resource Exhaustion & DoS',
    description: 'MCP server lacks authentication allowing unauthorized access and resource abuse',
    vulnerable_patterns: ['createServer\\s*\\(', 'app\\.listen\\s*\\(', 'serve\\s*\\(', 'StdioServerTransport', 'SSEServerTransport'],
    mcps_patterns: ['secureMCP', 'verifyPassport', 'authenticate', 'passport'],
    mcps_fix: 'Passport verification middleware — all requests require valid signed identity',
    mcps_api: 'secureMCP(), verifyPassport()'
  },
  {
    id: 'MCP-08',
    name: 'Insufficient Logging & Audit',
    description: 'No cryptographic audit trail for MCP operations',
    vulnerable_patterns: ['handleMessage', 'processRequest', 'onMessage', 'handler'],
    mcps_patterns: ['auditLog', 'onAudit', 'signMessage', 'audit'],
    mcps_fix: 'Signed audit trail — every message exchange is logged with cryptographic proof',
    mcps_api: 'auditLog(), onAudit()'
  },
  {
    id: 'MCP-09',
    name: 'Insecure MCP-to-MCP Communication',
    description: 'No origin validation between MCP servers',
    vulnerable_patterns: ['connect\\s*\\(', 'endpoint.*url', 'WebSocket', 'fetch\\s*\\('],
    mcps_patterns: ['validateOrigin', 'passport.*origin', 'origin'],
    mcps_fix: 'Origin binding — passports encode allowed origins, verified on each request',
    mcps_api: 'validateOrigin(), passport.origin'
  },
  {
    id: 'MCP-10',
    name: 'Context Window Pollution',
    description: 'Malicious data injected into shared context window across tool calls',
    vulnerable_patterns: ['prompt.*concat', 'context.*add', 'append.*message', 'messages\\.push'],
    mcps_patterns: ['signMessage', 'envelope', 'verifyMessage'],
    mcps_fix: 'Envelope isolation — signed message boundaries prevent context pollution',
    mcps_api: 'signMessage(), envelope'
  }
];

/**
 * Analyze files against OWASP MCP Top 10.
 * Returns status for each risk + overall MCPS detection.
 */
function analyzeMCP(files) {
  const allContent = files.map(f => f.content).join('\n');
  const results = [];
  let mcpsDetected = false;

  // Check for MCPS SDK presence (strict patterns to avoid false positives like "mcpServer")
  const mcpsImport = /require\s*\(\s*['"]mcp-secure['"]\s*\)|from\s+['"]mcp-secure['"]|mcp-secure|secureMCP\s*\(/i;
  if (mcpsImport.test(allContent)) {
    mcpsDetected = true;
  }

  for (const risk of MCP_RISKS) {
    if (risk.na) {
      results.push({
        ...risk,
        status: 'N/A',
        vulnerable: false,
        mitigated: false,
        current_state: 'Not applicable to code-level analysis',
        with_mcps: risk.mcps_fix
      });
      continue;
    }

    const hasVulnerable = risk.vulnerable_patterns.some(pat => {
      try { return new RegExp(pat, 'i').test(allContent); } catch { return false; }
    });

    const hasMitigation = risk.mcps_patterns.some(pat => {
      try { return new RegExp(pat, 'i').test(allContent); } catch { return false; }
    });

    let status, current_state;
    if (hasMitigation) {
      status = 'PASS';
      current_state = 'MCPS mitigation detected';
    } else if (hasVulnerable) {
      status = 'FAIL';
      current_state = 'Vulnerable pattern detected, no mitigation';
    } else {
      status = 'WARN';
      current_state = 'No evidence of vulnerability or mitigation';
    }

    results.push({
      ...risk,
      status,
      vulnerable: hasVulnerable,
      mitigated: hasMitigation,
      current_state,
      with_mcps: risk.mcps_fix
    });
  }

  const passCount = results.filter(r => r.status === 'PASS').length;
  const failCount = results.filter(r => r.status === 'FAIL').length;
  const warnCount = results.filter(r => r.status === 'WARN').length;
  const naCount = results.filter(r => r.status === 'N/A').length;
  const mitigatedCount = results.filter(r => r.mitigated).length;
  const applicable = results.length - naCount;

  return {
    risks: results,
    mcps_detected: mcpsDetected,
    summary: {
      total: results.length,
      pass: passCount,
      fail: failCount,
      warn: warnCount,
      na: naCount,
      mitigated: mitigatedCount,
      applicable,
      coverage: applicable > 0 ? `${mitigatedCount}/${applicable}` : '0/0'
    }
  };
}

module.exports = { analyzeMCP, MCP_RISKS };
