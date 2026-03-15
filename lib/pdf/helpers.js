'use strict';

// Print-optimized color palette
const COLORS = {
  primary: '#0891b2',
  green: '#16a34a',
  red: '#dc2626',
  amber: '#ea580c',
  text: '#1e293b',
  dim: '#64748b',
  border: '#e2e8f0',
  surface: '#f8fafc',
  coverBg: '#0a0e1a',
  coverAccent: '#22d3ee',
  white: '#ffffff',
  black: '#000000'
};

const SEVERITY_COLORS = {
  CRITICAL: COLORS.red,
  HIGH: '#a855f7',
  MEDIUM: COLORS.amber,
  LOW: COLORS.primary
};

const STATUS_COLORS = {
  PASS: COLORS.green,
  FAIL: COLORS.red,
  WARN: COLORS.amber,
  'N/A': COLORS.dim
};

const PAGE_WIDTH = 595.28; // A4
const PAGE_HEIGHT = 841.89;
const MARGIN = 50;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const FOOTER_Y = PAGE_HEIGHT - 40;
const SAFE_BOTTOM = PAGE_HEIGHT - 70; // content must not go below this

/**
 * Draw footer on current page. Call this right after addPage() or at end of page content.
 */
function drawFooter(doc, pageNumber) {
  const savedY = doc.y;
  doc.save();
  doc.fontSize(7).fillColor(COLORS.dim).font('Helvetica');
  doc.text('Powered by AgentSign | agentsign.dev', MARGIN, FOOTER_Y, { lineBreak: false });
  doc.text('CONFIDENTIAL', PAGE_WIDTH / 2 - 30, FOOTER_Y, { lineBreak: false });
  doc.text('Page ' + pageNumber, PAGE_WIDTH - MARGIN - 40, FOOTER_Y, { lineBreak: false });
  doc.restore();
  doc.y = savedY; // restore cursor so content rendering continues normally
}

function sectionHeader(doc, title) {
  checkPageBreak(doc, 50);
  doc.fontSize(16).fillColor(COLORS.primary).font('Helvetica-Bold');
  doc.text(title, MARGIN, doc.y + 10, { lineBreak: false });
  const underlineY = doc.y + 28;
  doc.moveTo(MARGIN, underlineY).lineTo(MARGIN + CONTENT_WIDTH, underlineY)
    .strokeColor(COLORS.primary).lineWidth(1.5).stroke();
  doc.y = underlineY + 10;
  doc.fillColor(COLORS.text).font('Helvetica');
  return doc.y;
}

function severityBadge(doc, severity, x, y, width = 65) {
  const color = SEVERITY_COLORS[severity] || COLORS.dim;
  const h = 16;
  doc.save();
  roundedRect(doc, x, y, width, h, 3, color);
  doc.fontSize(8).fillColor(COLORS.white).font('Helvetica-Bold');
  doc.text(severity, x, y + 3, { width, align: 'center', lineBreak: false });
  doc.restore();
  doc.fillColor(COLORS.text).font('Helvetica');
}

function roundedRect(doc, x, y, w, h, r, fillColor, strokeColor) {
  doc.save();
  if (fillColor) doc.fillColor(fillColor);
  if (strokeColor) doc.strokeColor(strokeColor);

  if (r <= 0) {
    // Simple rect
    if (fillColor && strokeColor) doc.rect(x, y, w, h).fillAndStroke();
    else if (fillColor) doc.rect(x, y, w, h).fill();
    else if (strokeColor) doc.rect(x, y, w, h).stroke();
    doc.restore();
    return;
  }

  doc.moveTo(x + r, y);
  doc.lineTo(x + w - r, y);
  doc.quadraticCurveTo(x + w, y, x + w, y + r);
  doc.lineTo(x + w, y + h - r);
  doc.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
  doc.lineTo(x + r, y + h);
  doc.quadraticCurveTo(x, y + h, x, y + h - r);
  doc.lineTo(x, y + r);
  doc.quadraticCurveTo(x, y, x + r, y);

  if (fillColor && strokeColor) doc.fillAndStroke();
  else if (fillColor) doc.fill();
  else if (strokeColor) doc.stroke();
  doc.restore();
}

function checkPageBreak(doc, neededHeight) {
  if (doc.y + neededHeight > SAFE_BOTTOM) {
    doc.addPage();
    doc.y = MARGIN;
    return true;
  }
  return false;
}

/**
 * Draw a code snippet box. Returns bottom y position.
 */
function codeBox(doc, code, x, width) {
  checkPageBreak(doc, 60);
  const padding = 8;

  // Measure text height first
  doc.font('Courier').fontSize(7);
  const textHeight = doc.heightOfString(code, { width: width - padding * 2 });
  const boxHeight = Math.min(textHeight + padding * 2, 120); // cap height

  const boxY = doc.y;
  roundedRect(doc, x, boxY, width, boxHeight, 4, '#f1f5f9');
  doc.fillColor('#475569');
  doc.text(code, x + padding, boxY + padding, {
    width: width - padding * 2,
    height: boxHeight - padding * 2,
    ellipsis: true
  });
  doc.y = boxY + boxHeight + 6;
  doc.fillColor(COLORS.text).font('Helvetica');
  return doc.y;
}

/**
 * Write text at absolute position WITHOUT advancing doc.y
 */
function textAt(doc, str, x, y, opts) {
  const savedY = doc.y;
  doc.text(str, x, y, { lineBreak: false, ...opts });
  doc.y = savedY;
}

module.exports = {
  COLORS,
  SEVERITY_COLORS,
  STATUS_COLORS,
  PAGE_WIDTH,
  PAGE_HEIGHT,
  MARGIN,
  CONTENT_WIDTH,
  FOOTER_Y,
  SAFE_BOTTOM,
  drawFooter,
  sectionHeader,
  severityBadge,
  roundedRect,
  checkPageBreak,
  codeBox,
  textAt
};
