'use strict';

const { COLORS, PAGE_WIDTH, PAGE_HEIGHT } = require('./helpers');

function renderCover(doc, report) {
  // Full dark background
  doc.rect(0, 0, PAGE_WIDTH, PAGE_HEIGHT).fill(COLORS.coverBg);

  // Shield logo (vector paths)
  const cx = PAGE_WIDTH / 2;
  const shieldY = 180;
  const s = 60;

  doc.save();
  // Outer shield
  doc.moveTo(cx, shieldY - s);
  doc.lineTo(cx + s * 0.8, shieldY - s * 0.5);
  doc.lineTo(cx + s * 0.8, shieldY + s * 0.2);
  doc.lineTo(cx, shieldY + s);
  doc.lineTo(cx - s * 0.8, shieldY + s * 0.2);
  doc.lineTo(cx - s * 0.8, shieldY - s * 0.5);
  doc.closePath().fillColor(COLORS.coverAccent).fill();

  // Inner dark shield
  const i = s * 0.7;
  doc.moveTo(cx, shieldY - i);
  doc.lineTo(cx + i * 0.8, shieldY - i * 0.5);
  doc.lineTo(cx + i * 0.8, shieldY + i * 0.2);
  doc.lineTo(cx, shieldY + i);
  doc.lineTo(cx - i * 0.8, shieldY + i * 0.2);
  doc.lineTo(cx - i * 0.8, shieldY - i * 0.5);
  doc.closePath().fillColor(COLORS.coverBg).fill();

  // Checkmark
  doc.moveTo(cx - 15, shieldY - 5);
  doc.lineTo(cx - 3, shieldY + 12);
  doc.lineTo(cx + 18, shieldY - 15);
  doc.lineWidth(4).strokeColor(COLORS.coverAccent).stroke();
  doc.restore();

  // Title
  const titleY = shieldY + s + 50;
  doc.fontSize(32).fillColor(COLORS.white).font('Helvetica-Bold');
  doc.text('MCP Security', 0, titleY, { width: PAGE_WIDTH, align: 'center', lineBreak: false });
  doc.text('Audit Report', 0, titleY + 40, { width: PAGE_WIDTH, align: 'center', lineBreak: false });

  // AgentSign brand
  doc.fontSize(14).fillColor(COLORS.coverAccent).font('Helvetica');
  doc.text('AgentSign', 0, titleY + 90, { width: PAGE_WIDTH, align: 'center', lineBreak: false });

  // Divider
  const divY = titleY + 120;
  doc.moveTo(cx - 100, divY).lineTo(cx + 100, divY)
    .strokeColor(COLORS.coverAccent).lineWidth(0.5).stroke();

  // Target info
  doc.fontSize(12).fillColor('#94a3b8');
  doc.text(report.name, 0, divY + 20, { width: PAGE_WIDTH, align: 'center', lineBreak: false });

  doc.fontSize(10).fillColor('#64748b');
  doc.text(new Date(report.scanned_at).toLocaleDateString('en-GB', {
    day: 'numeric', month: 'long', year: 'numeric'
  }), 0, divY + 42, { width: PAGE_WIDTH, align: 'center', lineBreak: false });

  doc.text('Report ID: ' + report.report_id, 0, divY + 60, { width: PAGE_WIDTH, align: 'center', lineBreak: false });

  // Footer
  doc.fontSize(8).fillColor('#475569');
  doc.text('Confidential | mcps-audit v' + report.scanner_version, 0, PAGE_HEIGHT - 60, {
    width: PAGE_WIDTH, align: 'center', lineBreak: false
  });

  // Reset y for next page
  doc.y = PAGE_HEIGHT;
}

module.exports = { renderCover };
