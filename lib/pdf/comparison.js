'use strict';

const { COLORS, MARGIN, CONTENT_WIDTH, sectionHeader, roundedRect, checkPageBreak, textAt } = require('./helpers');

function renderComparison(doc, report) {
  doc.addPage();
  sectionHeader(doc, 'Risk Comparison: WITHOUT MCPS vs WITH MCPS');

  const colW = (CONTENT_WIDTH - 20) / 2;
  const startY = doc.y + 5;

  // LEFT column header - red
  roundedRect(doc, MARGIN, startY, colW, 28, 4, COLORS.red);
  doc.fontSize(11).fillColor(COLORS.white).font('Helvetica-Bold');
  textAt(doc, 'CURRENT EXPOSURE', MARGIN, startY + 7, { width: colW, align: 'center' });

  // RIGHT column header - green
  const rightX = MARGIN + colW + 20;
  roundedRect(doc, rightX, startY, colW, 28, 4, COLORS.green);
  doc.fontSize(11).fillColor(COLORS.white).font('Helvetica-Bold');
  textAt(doc, 'WITH MCPS PROTECTION', rightX, startY + 7, { width: colW, align: 'center' });

  doc.y = startY + 38;

  // Risk rows
  const risks = report.mcp_analysis.risks.filter(r => !r.na);
  for (const risk of risks) {
    checkPageBreak(doc, 52);

    const rowY = doc.y;
    const rowH = 45;

    // Left: current state
    const leftBg = risk.status === 'FAIL' ? '#fef2f2' : (risk.status === 'WARN' ? '#fffbeb' : '#f0fdf4');
    roundedRect(doc, MARGIN, rowY, colW, rowH, 3, leftBg);

    doc.fontSize(8).fillColor(COLORS.dim).font('Helvetica-Bold');
    textAt(doc, risk.id, MARGIN + 8, rowY + 5);
    doc.fontSize(8).fillColor(COLORS.text).font('Helvetica-Bold');
    textAt(doc, risk.name, MARGIN + 50, rowY + 5);
    doc.fontSize(7).fillColor(risk.status === 'FAIL' ? COLORS.red : COLORS.dim).font('Helvetica');
    doc.text(risk.current_state, MARGIN + 50, rowY + 18, { width: colW - 65, lineBreak: true });

    // Status indicator
    const statusColor = risk.status === 'FAIL' ? COLORS.red : (risk.status === 'WARN' ? COLORS.amber : COLORS.green);
    doc.circle(MARGIN + colW - 15, rowY + 12, 4).fill(statusColor);

    // Right: with MCPS
    roundedRect(doc, rightX, rowY, colW, rowH, 3, '#f0fdf4');

    doc.fontSize(8).fillColor(COLORS.green).font('Helvetica-Bold');
    textAt(doc, 'MITIGATED', rightX + 8, rowY + 5);
    doc.fontSize(7).fillColor(COLORS.text).font('Helvetica');
    doc.text(risk.mcps_fix, rightX + 8, rowY + 18, { width: colW - 25, lineBreak: true });

    doc.fontSize(6).fillColor(COLORS.primary).font('Courier');
    textAt(doc, risk.mcps_api, rightX + 8, rowY + 34);

    doc.circle(rightX + colW - 15, rowY + 12, 4).fill(COLORS.green);

    doc.y = rowY + rowH + 4;
    doc.fillColor(COLORS.text).font('Helvetica');
  }

  // Bottom: Risk reduction summary
  checkPageBreak(doc, 60);
  doc.y += 8;
  const boxY = doc.y;
  roundedRect(doc, MARGIN, boxY, CONTENT_WIDTH, 50, 6, COLORS.coverBg);

  // "Risk Reduction" label
  doc.fontSize(10).fillColor('#94a3b8').font('Helvetica');
  textAt(doc, 'Risk Reduction', MARGIN + 15, boxY + 8);

  // Current score (red)
  doc.fontSize(22).fillColor(COLORS.red).font('Helvetica-Bold');
  textAt(doc, String(report.risk_score), MARGIN + 15, boxY + 22);

  // Arrow (ASCII safe)
  doc.fontSize(14).fillColor('#94a3b8').font('Helvetica');
  textAt(doc, '-->', MARGIN + 70, boxY + 26);

  // Mitigated score (green)
  doc.fontSize(22).fillColor(COLORS.green).font('Helvetica-Bold');
  textAt(doc, String(report.mitigated_score), MARGIN + 110, boxY + 22);

  // Reduction badge
  if (report.risk_reduction > 0) {
    roundedRect(doc, MARGIN + 160, boxY + 20, 100, 24, 4, COLORS.green);
    doc.fontSize(11).fillColor(COLORS.white).font('Helvetica-Bold');
    textAt(doc, report.risk_reduction + '% reduction', MARGIN + 160, boxY + 25, { width: 100, align: 'center' });
  }

  doc.y = boxY + 60;
  doc.fillColor(COLORS.text).font('Helvetica');
}

module.exports = { renderComparison };
