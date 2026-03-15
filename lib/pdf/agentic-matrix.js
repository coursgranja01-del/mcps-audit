'use strict';

const RULES = require('../rules');
const { COLORS, MARGIN, CONTENT_WIDTH, sectionHeader, severityBadge, roundedRect, checkPageBreak, textAt } = require('./helpers');

function renderAgenticMatrix(doc, report) {
  doc.addPage();
  sectionHeader(doc, 'OWASP Agentic AI Top 10 Coverage');

  doc.fontSize(9).fillColor(COLORS.text).font('Helvetica');
  doc.text(RULES.rules.length + ' rules checked | ' + report.total_findings + ' findings', MARGIN, doc.y, { lineBreak: false });
  doc.y += 18;

  const cols = [
    { label: 'Rule', w: 50 },
    { label: 'OWASP', w: 45 },
    { label: 'MITRE', w: 55 },
    { label: 'STRIDE', w: 95 },
    { label: 'Severity', w: 65 },
    { label: 'Findings', w: 45 },
    { label: 'Status', w: 40 }
  ];

  function renderHeader() {
    const hY = doc.y;
    roundedRect(doc, MARGIN, hY, CONTENT_WIDTH, 22, 3, COLORS.primary);
    doc.fontSize(7).fillColor(COLORS.white).font('Helvetica-Bold');
    let hx = MARGIN + 3;
    for (const col of cols) {
      textAt(doc, col.label, hx, hY + 6);
      hx += col.w;
    }
    doc.y = hY + 26;
  }

  renderHeader();

  // Count findings per rule
  const ruleFindings = {};
  for (const f of report.findings) {
    ruleFindings[f.rule] = (ruleFindings[f.rule] || 0) + 1;
  }

  for (let i = 0; i < RULES.rules.length; i++) {
    const rule = RULES.rules[i];
    const rowH = 24;
    const count = ruleFindings[rule.id] || 0;

    if (checkPageBreak(doc, rowH + 5)) {
      renderHeader();
    }

    const rowY = doc.y;
    const bg = i % 2 === 0 ? COLORS.surface : COLORS.white;
    roundedRect(doc, MARGIN, rowY, CONTENT_WIDTH, rowH, 0, bg);

    let x = MARGIN + 3;

    doc.fontSize(7).fillColor(COLORS.text).font('Helvetica-Bold');
    textAt(doc, rule.id, x, rowY + 7);
    x += cols[0].w;

    doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
    textAt(doc, rule.owasp, x, rowY + 7);
    x += cols[1].w;

    textAt(doc, rule.attack, x, rowY + 7);
    x += cols[2].w;

    doc.fontSize(6);
    textAt(doc, rule.stride, x, rowY + 7);
    x += cols[3].w;

    severityBadge(doc, rule.severity, x, rowY + 4, cols[4].w - 5);
    x += cols[4].w;

    doc.fontSize(8).fillColor(count > 0 ? COLORS.red : COLORS.green).font('Helvetica-Bold');
    textAt(doc, String(count), x + 10, rowY + 7);
    x += cols[5].w;

    const sc = count > 0 ? COLORS.red : COLORS.green;
    doc.circle(x + 12, rowY + 12, 4).fill(sc);

    doc.y = rowY + rowH + 1;
  }

  doc.y += 10;
  doc.fillColor(COLORS.text).font('Helvetica');
}

module.exports = { renderAgenticMatrix };
