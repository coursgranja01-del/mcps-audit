/**
 * Clean MCP server using mcp-secure — for testing mcps-audit scanner.
 * Should produce PASS or low-severity results.
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  secureMCP,
  createPassport,
  signPassport,
  verifyPassport,
  signTool,
  verifyTool,
  signMessage,
  verifyMessage,
  validateOrigin,
  auditLog
} = require('mcp-secure');
const winston = require('winston');

// Logging configured
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [new winston.transports.Console()]
});

// Secrets from environment (not hardcoded)
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;

// Create MCP server with MCPS security
const server = new Server({
  name: 'secure-test-server',
  version: '1.0.0'
}, {
  capabilities: { tools: {} }
});

// Passport-based identity
const passport = createPassport({
  name: 'secure-test-server',
  capabilities: ['read', 'write'],
  origin: 'https://secure-server.example.com'
});

const signedPassport = signPassport(passport);

// Signed tool definitions
const tools = [
  signTool({
    name: 'getData',
    description: 'Fetch data from the database',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string' }
      }
    }
  }),
  signTool({
    name: 'processData',
    description: 'Process data with validation',
    inputSchema: {
      type: 'object',
      properties: {
        data: { type: 'string' }
      }
    }
  })
];

// Verify tools on load
for (const tool of tools) {
  if (!verifyTool(tool)) {
    throw new Error(`Tool integrity check failed: ${tool.name}`);
  }
}

// Secure middleware with authentication
secureMCP(server, {
  passport: signedPassport,
  requireAuth: true,
  auditLog: true
});

// Tool handler — no eval, no exec
server.setRequestHandler('tools/call', async (request) => {
  const { name, arguments: args } = request.params;

  // Validate passport
  if (!verifyPassport(request.passport)) {
    logger.warn('Invalid passport', { name, passport: request.passport_id });
    throw new Error('Unauthorized');
  }

  // Validate origin
  validateOrigin(request);

  // Audit log
  auditLog({
    action: 'tool_call',
    tool: name,
    agent: request.passport_id,
    timestamp: new Date().toISOString()
  });

  // Signed message envelope
  const message = signMessage({
    tool: name,
    args,
    result: 'processed'
  });

  logger.info('Tool called', { name, agent: request.passport_id });
  return message;
});

// Connect with signed transport
const transport = new StdioServerTransport();
server.connect(transport);

logger.info('Secure MCP server started');
