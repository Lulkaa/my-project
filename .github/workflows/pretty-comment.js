const fs = require('fs');
const path = './semgrep_scan_results.txt';

if (!fs.existsSync(path)) {
  console.error(`Input file not found: ${path}`);
  process.exit(1);
}

const raw = fs.readFileSync(path, 'utf8');
const lines = raw.split(/\r?\n/);

const findings = [];
let current = null;
let captureMessage = [];

// Рядок, що схожий на шлях до файлу
const fileLineRe = /^\s*([^\s].*?\.(?:js|ts|jsx|tsx|py|java|go|rb))\s*$/i;
// Рядок із нумерацією типу "17┆ ..."
const numberedLineRe = /^\s*\d+┆\s+.*$/;
// Патерни ризикових рядків
const interestingCodeRe = /(const\s+regex\s*=\s*new\s+RegExp)|\b(Nested regex|vulnerable to backtracking|ReDoS)\b/i;

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
const red = (s) => `<span style="color:red">${escapeHtml(s)}</span>`;

// Нормалізувати початкові пробіли перед номером рядка: "           17┆ ..." -> "17┆ ..."
function normalizeLeadingIndent(line) {
  return line.replace(/^\s+(\d+┆\s+)/, '$1');
}

// Обгортка рядка для код-блоку (без <div> усередині)
function codeLine(line, highlight=false) {
  const normalized = normalizeLeadingIndent(line);
  const esc = escapeHtml(normalized);
  return highlight ? `<mark>${esc}</mark>` : esc;
}

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];

  const fileMatch = line.match(fileLineRe);
  if (fileMatch) {
    if (current) {
      current.message = captureMessage.join('\n').trim();
      findings.push(current);
    }
    current = { file: fileMatch[1].trim(), rule: null, message: '', codeLines: [] };
    captureMessage = [];
    continue;
  }

  if (!current) continue;

  if (!current.rule) {
    if (line.includes('semgrep') || line.match(/[a-z0-9_.-]+-rule/i) || line.includes('detect-')) {
      current.rule = line.trim();
      continue;
    }
  }

  if (numberedLineRe.test(line)) {
    current.codeLines.push({ raw: line, highlight: true });
    continue;
  }

  if (interestingCodeRe.test(line)) {
    current.codeLines.push({ raw: line, highlight: true });
    continue;
  }

  if (line.trim() === '') continue;

  captureMessage.push(line.trim());
}

if (current) {
  current.message = captureMessage.join('\n').trim();
  findings.push(current);
}

const hasFindings = findings.length > 0;
const header = hasFindings
  ? `### Semgrep found ${findings.length} findings`
  : `### Semgrep: no findings found`;

let bodyParts = [header, ''];

if (hasFindings) {
  bodyParts.push('**Details:**', '');
  for (const f of findings) {
    const fileHtml = red(f.file);
    const ruleLine = f.rule ? `<div><em>${escapeHtml(f.rule.trim())}</em></div>` : '';
    const messageHtml = f.message ? `<div>${escapeHtml(f.message)}</div>` : '';

    let codeBlock = '';
    if (f.codeLines?.length) {
      const inner = f.codeLines
        .map(cl => codeLine(cl.raw, cl.highlight || interestingCodeRe.test(cl.raw)))
        .join('\n');
      codeBlock = `<div style="margin-top:8px;margin-bottom:8px"><pre style="background:#f6f8fa;padding:8px;border-radius:6px;overflow:auto"><code>${inner}</code></pre></div>`;
    }

    const itemHtml =
      `- **File:** ${fileHtml}\n` +
      (ruleLine ? `  \n  ${ruleLine}\n` : '') +
      (messageHtml ? `  \n  ${messageHtml}\n` : '') +
      `\n${codeBlock}\n`;

    bodyParts.push(itemHtml);
  }
}

const body = bodyParts.join('\n');

fs.writeFileSync('pretty-comment1.md', body, 'utf8');
console.log('Wrote pretty-comment1.md');

try {
  const ghOut = process.env.GITHUB_OUTPUT;
  if (ghOut) {
    fs.writeFileSync(ghOut, `has_findings=${hasFindings}\n`, { flag: 'a' });
  } else {
    fs.writeFileSync('./github_output.txt', `has_findings=${hasFindings}\n`, { flag: 'a' });
  }
} catch (e) {
  console.warn('Could not write to GITHUB_OUTPUT:', e.message);
}

console.log(`has_findings=${hasFindings}`);
