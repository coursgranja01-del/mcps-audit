'use strict';

const fs = require('fs');
const path = require('path');

const INCLUDE_EXT = new Set(['.js', '.ts', '.py', '.json', '.mjs', '.cjs']);
const EXCLUDE_DIRS = new Set(['node_modules', 'dist', '.git', 'venv', '__pycache__', '.next', 'build', 'coverage']);
const MAX_FILES = 500;
const MAX_FILE_SIZE = 500 * 1024; // 500KB

function isBinary(buf) {
  for (let i = 0; i < Math.min(buf.length, 512); i++) {
    if (buf[i] === 0) return true;
  }
  return false;
}

function langFromExt(ext) {
  const map = {
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.ts': 'typescript', '.py': 'python', '.json': 'json'
  };
  return map[ext] || 'unknown';
}

function collectFiles(targetPath) {
  const files = [];
  const stats = fs.statSync(targetPath);

  if (stats.isFile()) {
    const ext = path.extname(targetPath).toLowerCase();
    if (INCLUDE_EXT.has(ext) && stats.size <= MAX_FILE_SIZE) {
      const buf = fs.readFileSync(targetPath);
      if (!isBinary(buf)) {
        files.push({
          path: targetPath,
          content: buf.toString('utf8'),
          language: langFromExt(ext),
          size: stats.size
        });
      }
    }
    return files;
  }

  const walk = (dir) => {
    if (files.length >= MAX_FILES) return;
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES) break;
      if (entry.name.startsWith('.') && entry.isDirectory()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!EXCLUDE_DIRS.has(entry.name)) walk(full);
      } else {
        const ext = path.extname(entry.name).toLowerCase();
        if (!INCLUDE_EXT.has(ext)) continue;
        let st;
        try { st = fs.statSync(full); } catch { continue; }
        if (st.size > MAX_FILE_SIZE || st.size === 0) continue;
        const buf = fs.readFileSync(full);
        if (isBinary(buf)) continue;
        files.push({
          path: full,
          content: buf.toString('utf8'),
          language: langFromExt(ext),
          size: st.size
        });
      }
    }
  };

  walk(targetPath);
  return files;
}

module.exports = { collectFiles };
