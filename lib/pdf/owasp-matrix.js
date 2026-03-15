'use strict';

const { COLORS, MARGIN, CONTENT_WIDTH, sectionHeader, roundedRect, checkPageBreak, textAt } = require('./helpers');

function renderOwaspMatrix(doc, report) {
  doc.addPage();
  sectionHeader(doc, 'OWASP MCP Top 10 Compliance');

  const risks = report.mcp_analysis.risks;
  const summary = report.mcp_analysis.summary;

  doc.fontSize(10).fillColor(COLORS.text).font('Helvetica');
  doc.text('Coverage: ' + summary.coverage + ' risks mitigated by MCPS', MARGIN, doc.y, { lineBreak: false });
  doc.y += 18;

  // Column widths
  const cols = [
    { label: 'ID', w: 45 },
    { label: 'Risk', w: 155 },
    { label: 'Status', w: 45 },
    { label: 'Current State', w: 125 },
    { label: 'With MCPS', w: 125 }
  ];

  function renderHeader() {
    const hY = doc.y;
    roundedRect(doc, MARGIN, hY, CONTENT_WIDTH, 22, 3, COLORS.primary);
    doc.fontSize(7).fillColor(COLORS.white).font('Helvetica-Bold');
    let hx = MARGIN + 5;
    for (const col of cols) {
      textAt(doc, col.label, hx, hY + 6);
      hx += col.w;
    }
    doc.y = hY + 26;
  }

  renderHeader();

  for (let i = 0; i < risks.length; i++) {
    const risk = risks[i];
    const rowH = 28;

    if (checkPageBreak(doc, rowH + 5)) {
      renderHeader();
    }

    const rowY = doc.y;
    const bg = i % 2 === 0 ? COLORS.surface : COLORS.white;
    roundedRect(doc, MARGIN, rowY, CONTENT_WIDTH, rowH, 0, bg);

    let x = MARGIN + 5;

    doc.fontSize(7).fillColor(COLORS.text).font('Helvetica-Bold');
    textAt(doc, risk.id, x, rowY + 5);
    x += cols[0].w;

    doc.fontSize(7).fillColor(COLORS.text).font('Helvetica');
    textAt(doc, risk.name, x, rowY + 5);
    x += cols[1].w;

    const statusColors = { PASS: COLORS.green, FAIL: COLORS.red, WARN: COLORS.amber, 'N/A': COLORS.dim };
    doc.circle(x + 6, rowY + 12, 4).fill(statusColors[risk.status] || COLORS.dim);
    doc.fontSize(7).fillColor(COLORS.text).font('Helvetica-Bold');
    textAt(doc, risk.status, x + 14, rowY + 8);
    x += cols[2].w;

    doc.fontSize(6).fillColor(COLORS.dim).font('Helvetica');
    doc.text(risk.current_state, x, rowY + 4, { width: cols[3].w - 5, height: rowH - 4 });
    x += cols[3].w;

    doc.fontSize(6).fillColor(COLORS.green).font('Helvetica');
    doc.text(risk.with_mcps, x, rowY + 4, { width: cols[4].w - 5, height: rowH - 4 });

    doc.y = rowY + rowH + 1;
  }

  doc.y += 15;
  doc.fillColor(COLORS.text).font('Helvetica');

  // Quick Fix box - all text positioned absolutely within box
  checkPageBreak(doc, 55);
  const boxY = doc.y;
  const boxH = 45;
  roundedRect(doc, MARGIN, boxY, CONTENT_WIDTH, boxH, 4, '#ecfeff');

  doc.fontSize(9).fillColor(COLORS.primary).font('Helvetica-Bold');
  textAt(doc, 'Quick Fix', MARGIN + 12, boxY + 8);

  doc.fontSize(9).fillColor(COLORS.text).font('Courier');
  textAt(doc, 'npm install mcp-secure', MARGIN + 85, boxY + 8);

  doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
  doc.text('Add MCPS to your MCP server to automatically mitigate the risks marked FAIL above.',
    MARGIN + 12, boxY + 24, { width: CONTENT_WIDTH - 24, lineBreak: true });

  doc.y = boxY + boxH + 8;
}

module.exports = { renderOwaspMatrix };
