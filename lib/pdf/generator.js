'use strict';

const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const { drawFooter, PAGE_WIDTH, PAGE_HEIGHT, MARGIN } = require('./helpers');
const { renderCover } = require('./cover');
const { renderExecutive } = require('./executive');
const { renderComparison } = require('./comparison');
const { renderOwaspMatrix } = require('./owasp-matrix');
const { renderAgenticMatrix } = require('./agentic-matrix');
const { renderFindings } = require('./findings');
const { renderRemediation } = require('./remediation');
const { renderMethodology } = require('./methodology');

function generatePDF(report, outputPath) {
  return new Promise((resolve, reject) => {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    // Track page count for footers
    let pageCount = 1;

    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
      bufferPages: false, // NO buffering - prevents phantom blank pages
      autoFirstPage: true,
      info: {
        Title: 'MCP Security Audit -- ' + report.name,
        Author: 'AgentSign',
        Subject: 'OWASP MCP Top 10 + Agentic AI Security Audit',
        Creator: 'mcps-audit v' + report.scanner_version
      }
    });

    // Add footer to every new page automatically (except cover)
    doc.on('pageAdded', () => {
      pageCount++;
      // Draw footer on the NEW page
      drawFooter(doc, pageCount);
    });

    const stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);

    try {
      // Page 1: Cover (no footer - cover has its own)
      renderCover(doc, report);

      // Page 2: Executive Summary (addPage triggers footer via event)
      doc.addPage();
      renderExecutive(doc, report);

      // Pages 3+: Comparison
      renderComparison(doc, report);

      // OWASP MCP Top 10 Matrix
      renderOwaspMatrix(doc, report);

      // Agentic AI Matrix
      renderAgenticMatrix(doc, report);

      // Detailed Findings
      renderFindings(doc, report);

      // Remediation Checklist
      renderRemediation(doc, report);

      // Methodology (last)
      renderMethodology(doc, report);

      doc.end();
    } catch (err) {
      doc.end();
      reject(err);
      return;
    }

    stream.on('finish', resolve);
    stream.on('error', reject);
  });
}

module.exports = { generatePDF };
