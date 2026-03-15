'use strict';

const { COLORS, MARGIN, CONTENT_WIDTH, sectionHeader, roundedRect, checkPageBreak, textAt } = require('./helpers');

function renderRemediation(doc, report) {
  if (report.findings.length === 0) return;

  doc.addPage();
  sectionHeader(doc, 'Remediation Checklist');

  doc.fontSize(9).fillColor(COLORS.text).font('Helvetica');
  doc.text('Prioritized by severity. Address CRITICAL items first.', MARGIN, doc.y, { lineBreak: false });
  doc.y += 16;

  // Quick win callout - absolute positioning inside box
  checkPageBreak(doc, 45);
  const qwY = doc.y;
  roundedRect(doc, MARGIN, qwY, CONTENT_WIDTH, 38, 4, '#ecfeff');

  doc.fontSize(9).fillColor(COLORS.primary).font('Helvetica-Bold');
  textAt(doc, 'Quick Win', MARGIN + 10, qwY + 6);

  doc.fontSize(9).fillColor(COLORS.text).font('Courier');
  textAt(doc, 'npm install mcp-secure', MARGIN + 85, qwY + 6);

  doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
  doc.text('Adds cryptographic passports, signed messages, tool verification, and audit logging.',
    MARGIN + 10, qwY + 22, { width: CONTENT_WIDTH - 20, lineBreak: true });

  doc.y = qwY + 44;

  // Group findings by severity
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const sevColors = {
    CRITICAL: { bg: '#fef2f2', fg: COLORS.red },
    HIGH: { bg: '#fdf4ff', fg: '#a855f7' },
    MEDIUM: { bg: '#fffbeb', fg: COLORS.amber },
    LOW: { bg: '#ecfeff', fg: COLORS.primary }
  };

  // Deduplicate by rule
  const seen = new Set();
  const unique = report.findings.filter(f => {
    if (seen.has(f.rule)) return false;
    seen.add(f.rule);
    return true;
  });

  for (const sev of order) {
    const items = unique.filter(f => f.severity === sev);
    if (items.length === 0) continue;

    checkPageBreak(doc, 28);
    const sc = sevColors[sev];

    const sevHeaderY = doc.y;
    roundedRect(doc, MARGIN, sevHeaderY, CONTENT_WIDTH, 20, 3, sc.bg);
    doc.fontSize(9).fillColor(sc.fg).font('Helvetica-Bold');
    textAt(doc, sev + ' (' + items.length + ')', MARGIN + 10, sevHeaderY + 5);
    doc.y = sevHeaderY + 24;

    for (const f of items) {
      checkPageBreak(doc, 28);

      const itemY = doc.y;

      // Checkbox
      doc.rect(MARGIN + 10, itemY + 1, 10, 10).strokeColor(COLORS.border).lineWidth(0.5).stroke();

      // Rule title
      doc.fontSize(8).fillColor(COLORS.text).font('Helvetica-Bold');
      doc.text(f.rule + ': ' + f.check.replace(/_/g, ' '), MARGIN + 28, itemY, { width: CONTENT_WIDTH - 40, lineBreak: false });

      // First remediation step
      doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
      const firstStep = f.runbook.split(/\d+\.\s/).filter(Boolean)[0] || f.runbook;
      doc.text(firstStep.trim(), MARGIN + 28, itemY + 12, { width: CONTENT_WIDTH - 40 });
      doc.y += 4;
    }

    doc.y += 4;
  }

  doc.fillColor(COLORS.text).font('Helvetica');
}

module.exports = { renderRemediation };
