'use strict';

const { COLORS, MARGIN, CONTENT_WIDTH, sectionHeader, roundedRect, checkPageBreak, textAt } = require('./helpers');

function renderMethodology(doc, report) {
  doc.addPage();
  sectionHeader(doc, 'Methodology & Standards');

  const items = [
    { label: 'Scanner', value: 'mcps-audit v' + report.scanner_version },
    { label: 'Rules Version', value: report.rules_version },
    { label: 'Scanned At', value: new Date(report.scanned_at).toLocaleString('en-GB') },
    { label: 'Report ID', value: report.report_id }
  ];

  // Info table
  const rowH = 22;
  for (let i = 0; i < items.length; i++) {
    const rowY = doc.y;
    const bg = i % 2 === 0 ? COLORS.surface : COLORS.white;
    roundedRect(doc, MARGIN, rowY, CONTENT_WIDTH, rowH, 0, bg);
    doc.fontSize(8).fillColor(COLORS.dim).font('Helvetica');
    textAt(doc, items[i].label, MARGIN + 10, rowY + 6);
    doc.fontSize(8).fillColor(COLORS.text).font('Helvetica-Bold');
    textAt(doc, items[i].value, MARGIN + 130, rowY + 6);
    doc.y = rowY + rowH;
  }

  doc.y += 20;

  sectionHeader(doc, 'Referenced Standards');

  const standards = [
    {
      title: 'OWASP MCP Top 10',
      desc: 'Security risks for Model Context Protocol servers and clients.',
      url: 'owasp.org/www-project-mcp-top-10'
    },
    {
      title: 'OWASP Agentic AI Top 10',
      desc: 'Security risks for autonomous AI agents.',
      url: 'owasp.org/www-project-agentic-ai-top-10'
    },
    {
      title: 'MCPS -- IETF Internet-Draft',
      desc: 'Cryptographic security layer for MCP: draft-sharif-mcps-secure-mcp.',
      url: 'datatracker.ietf.org/doc/draft-sharif-mcps-secure-mcp'
    },
    {
      title: 'MITRE ATT&CK',
      desc: 'Adversary tactics and techniques knowledge base.',
      url: 'attack.mitre.org'
    },
    {
      title: 'STRIDE Threat Model',
      desc: 'Microsoft threat classification framework.',
      url: 'microsoft.com/en-us/security/blog/stride'
    }
  ];

  for (const std of standards) {
    checkPageBreak(doc, 40);
    const y = doc.y;
    doc.fontSize(9).fillColor(COLORS.text).font('Helvetica-Bold');
    textAt(doc, std.title, MARGIN + 10, y);
    doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
    textAt(doc, std.desc, MARGIN + 10, y + 12);
    doc.fontSize(7).fillColor(COLORS.primary);
    textAt(doc, std.url, MARGIN + 10, y + 22);
    doc.y = y + 34;
  }

  // Contact box
  doc.y += 10;
  checkPageBreak(doc, 55);
  const boxY = doc.y;
  roundedRect(doc, MARGIN, boxY, CONTENT_WIDTH, 45, 4, COLORS.coverBg);
  doc.fontSize(10).fillColor(COLORS.coverAccent).font('Helvetica-Bold');
  textAt(doc, 'AgentSign', MARGIN + 15, boxY + 10);
  doc.fontSize(8).fillColor('#94a3b8').font('Helvetica');
  textAt(doc, 'Cryptographic identity and security for AI agents', MARGIN + 15, boxY + 24);
  doc.fontSize(8).fillColor(COLORS.coverAccent);
  textAt(doc, 'agentsign.dev', MARGIN + 15, boxY + 36);

  doc.y = boxY + 55;
  doc.fillColor(COLORS.text).font('Helvetica');
}

module.exports = { renderMethodology };
