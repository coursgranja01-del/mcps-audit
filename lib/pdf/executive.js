'use strict';

const { COLORS, MARGIN, CONTENT_WIDTH, sectionHeader, roundedRect, checkPageBreak, textAt } = require('./helpers');

function renderExecutive(doc, report) {
  sectionHeader(doc, 'Executive Summary');

  const startY = doc.y + 5;

  // Verdict badge
  const verdictColors = { PASS: COLORS.green, WARN: COLORS.amber, FAIL: COLORS.red };
  const vc = verdictColors[report.verdict] || COLORS.dim;

  roundedRect(doc, MARGIN, startY, 130, 50, 6, vc);
  doc.fontSize(24).fillColor(COLORS.white).font('Helvetica-Bold');
  textAt(doc, report.verdict, MARGIN, startY + 12, { width: 130, align: 'center' });

  // Risk score bar
  const barX = MARGIN + 150;
  const barY = startY + 10;
  const barW = CONTENT_WIDTH - 160;
  const barH = 24;

  doc.fontSize(9).fillColor(COLORS.dim).font('Helvetica');
  textAt(doc, 'Risk Score', barX, startY - 2);

  // Background bar
  roundedRect(doc, barX, barY, barW, barH, 4, '#e2e8f0');

  // Filled bar
  const fillW = Math.max(4, (report.risk_score / 100) * barW);
  let barColor = COLORS.green;
  if (report.risk_score > 70) barColor = COLORS.red;
  else if (report.risk_score > 40) barColor = COLORS.amber;
  else if (report.risk_score > 20) barColor = '#eab308';
  roundedRect(doc, barX, barY, fillW, barH, 4, barColor);

  doc.fontSize(12).fillColor(COLORS.white).font('Helvetica-Bold');
  textAt(doc, report.risk_score + '/100', barX, barY + 5, { width: barW, align: 'center' });

  // Severity count boxes
  const boxRowY = startY + 70;
  const boxW = (CONTENT_WIDTH - 30) / 4;
  const boxH = 50;
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const sevColors = {
    CRITICAL: { bg: '#fef2f2', fg: COLORS.red },
    HIGH: { bg: '#fdf4ff', fg: '#a855f7' },
    MEDIUM: { bg: '#fffbeb', fg: COLORS.amber },
    LOW: { bg: '#ecfeff', fg: COLORS.primary }
  };

  for (let i = 0; i < 4; i++) {
    const sev = severities[i];
    const x = MARGIN + i * (boxW + 10);
    const sc = sevColors[sev];

    roundedRect(doc, x, boxRowY, boxW, boxH, 4, sc.bg);
    roundedRect(doc, x, boxRowY, boxW, boxH, 4, null, sc.fg);

    doc.fontSize(22).fillColor(sc.fg).font('Helvetica-Bold');
    textAt(doc, String(report.severity_counts[sev]), x, boxRowY + 6, { width: boxW, align: 'center' });
    doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
    textAt(doc, sev, x, boxRowY + 32, { width: boxW, align: 'center' });
  }

  // Scan scope info box
  const scopeY = boxRowY + boxH + 20;
  roundedRect(doc, MARGIN, scopeY, CONTENT_WIDTH, 55, 4, COLORS.surface);

  const infoY = scopeY + 10;
  const col1 = MARGIN + 15;
  const col2 = MARGIN + CONTENT_WIDTH / 3;
  const col3 = MARGIN + (CONTENT_WIDTH * 2) / 3;

  doc.fontSize(9).fillColor(COLORS.dim).font('Helvetica');
  textAt(doc, 'SCAN SCOPE', col1, infoY);
  doc.fontSize(11).fillColor(COLORS.text).font('Helvetica-Bold');
  textAt(doc, report.scope.files + ' files', col1, infoY + 14);
  doc.fontSize(8).fillColor(COLORS.dim).font('Helvetica');
  textAt(doc, report.scope.lines.toLocaleString() + ' lines', col1, infoY + 28);

  doc.fontSize(9).fillColor(COLORS.dim);
  textAt(doc, 'LANGUAGES', col2, infoY);
  const langs = Object.entries(report.scope.languages).map(([k, v]) => k + ' (' + v + ')').join(', ');
  doc.fontSize(10).fillColor(COLORS.text).font('Helvetica-Bold');
  textAt(doc, langs, col2, infoY + 14);

  doc.fontSize(9).fillColor(COLORS.dim).font('Helvetica');
  textAt(doc, 'MCPS SDK', col3, infoY);
  doc.fontSize(11).font('Helvetica-Bold');
  doc.fillColor(report.mcps_detected ? COLORS.green : COLORS.red);
  textAt(doc, report.mcps_detected ? 'Detected' : 'Not Found', col3, infoY + 14);

  doc.y = scopeY + 65;
  doc.fillColor(COLORS.text).font('Helvetica');
}

module.exports = { renderExecutive };
