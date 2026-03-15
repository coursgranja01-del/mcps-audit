'use strict';

const path = require('path');
const { COLORS, MARGIN, CONTENT_WIDTH, sectionHeader, severityBadge, roundedRect, checkPageBreak, codeBox, textAt } = require('./helpers');

function renderFindings(doc, report) {
  if (report.findings.length === 0) return;

  doc.addPage();
  sectionHeader(doc, 'Detailed Findings');

  for (let i = 0; i < report.findings.length; i++) {
    const f = report.findings[i];

    checkPageBreak(doc, 140);

    // Finding header bar
    const headerY = doc.y;
    roundedRect(doc, MARGIN, headerY, CONTENT_WIDTH, 26, 4, COLORS.surface);

    doc.fontSize(9).fillColor(COLORS.text).font('Helvetica-Bold');
    textAt(doc, '#' + (i + 1) + '  ' + f.rule + ' -- ' + f.check.replace(/_/g, ' ').toUpperCase(), MARGIN + 8, headerY + 7);
    severityBadge(doc, f.severity, MARGIN + CONTENT_WIDTH - 75, headerY + 5, 65);
    doc.y = headerY + 30;

    // OWASP refs
    doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
    doc.text('OWASP: ' + f.owasp + '  |  MITRE: ' + f.attack + '  |  STRIDE: ' + f.stride,
      MARGIN + 8, doc.y, { lineBreak: false });
    doc.y += 12;

    // Description
    doc.fontSize(8).fillColor(COLORS.text).font('Helvetica');
    doc.text(f.description, MARGIN + 8, doc.y, { width: CONTENT_WIDTH - 16 });
    doc.y += 4;

    // File path
    const relPath = path.relative(report.target, f.file);
    doc.fontSize(8).fillColor(COLORS.primary).font('Courier');
    doc.text(relPath + ':' + f.line, MARGIN + 8, doc.y, { lineBreak: false });
    doc.y += 12;

    // Detail
    doc.fontSize(8).fillColor(COLORS.red).font('Helvetica-Bold');
    doc.text(f.detail, MARGIN + 8, doc.y, { width: CONTENT_WIDTH - 16 });
    doc.y += 4;

    // Code snippet
    if (f.snippet) {
      codeBox(doc, f.snippet, MARGIN + 8, CONTENT_WIDTH - 16);
    }

    // Remediation
    checkPageBreak(doc, 40);
    doc.fontSize(8).fillColor(COLORS.green).font('Helvetica-Bold');
    doc.text('Remediation:', MARGIN + 8, doc.y, { lineBreak: false });
    doc.y += 10;
    doc.fontSize(7).fillColor(COLORS.text).font('Helvetica');
    doc.text(f.runbook, MARGIN + 8, doc.y, { width: CONTENT_WIDTH - 16 });
    doc.y += 6;

    // MCPS note for applicable rules
    const mcpsRules = new Set(['AS-006', 'AS-008', 'AS-012']);
    if (mcpsRules.has(f.rule)) {
      checkPageBreak(doc, 25);
      const noteY = doc.y;
      roundedRect(doc, MARGIN + 8, noteY, CONTENT_WIDTH - 16, 18, 3, '#ecfeff');
      doc.fontSize(7).fillColor(COLORS.primary).font('Helvetica-Bold');
      textAt(doc, 'MCPS Quick Fix: npm install mcp-secure', MARGIN + 14, noteY + 4);
      doc.y = noteY + 22;
    }

    // Divider
    doc.y += 4;
    if (i < report.findings.length - 1) {
      doc.moveTo(MARGIN + 20, doc.y).lineTo(MARGIN + CONTENT_WIDTH - 20, doc.y)
        .strokeColor(COLORS.border).lineWidth(0.5).stroke();
      doc.y += 8;
    }
  }
}

module.exports = { renderFindings };
