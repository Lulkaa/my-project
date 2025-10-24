const fs = require('fs');
const path = './semgrep_scan_results.txt';

if (!fs.existsSync(path)) {
  console.error(`Input file not found: ${path}`);
  process.exit(1);
}

const raw = fs.readFileSync(path, 'utf8');
const lines = raw.split(/\r?\n/);

// Знахідки
const findings = [];

// Стан парсера
let current = null;
let captureMessage = [];


// Рядок, який виглядає як шлях до файлу
const fileLineRe = /^\s*([^\s].*?\.(?:js|ts|jsx|tsx|py|java|go|rb))\s*$/i;

// Рядок коду з нумерацією як "17┆ ..." (не відкидаємо префікс)
const numberedLineRe = /^\s*\d+┆\s+.*$/;

// Рядки, які треба підсвічувати жовтим
const interestingCodeRe = /(const\s+regex\s*=\s*new\s+RegExp)|\b(Nested regex|vulnerable to backtracking|ReDoS)\b/i;

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

const red = (s) => `<span style="color:red">${escapeHtml(s)}</span>`;
// Якщо GitHub ріже style, заміни вище на: const red = (s) => `🔴 ${'`'+s+'`'}`;

const wrapCode = (line, highlight=false) => {
  const esc = escapeHtml(line);
  // без додаткових стилів — лише <mark> для підсвічування
  return highlight ? `<div><mark>${esc}</mark></div>` : `<div>${esc}</div>`;
};

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];

  // Новий файл?
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

  // Спробуємо вловити строку з rule/id
  if (!current.rule) {
    if (line.includes('semgrep') || line.match(/[a-z0-9_.-]+-rule/i) || line.includes('detect-')) {
      current.rule = line.trim();
      continue;
    }
  }

  // Рядок коду (із нумерацією) — залишаємо як є
  if (numberedLineRe.test(line)) {
    const shouldHighlight = true; // будь-який такий рядок — жовтий, як ти просив
    current.codeLines.push({ raw: line, highlight: shouldHighlight });
    continue;
  }

  // Звичайний код (без нумерації), але який містить цікаві патерни
  if (interestingCodeRe.test(line)) {
    current.codeLines.push({ raw: line, highlight: true });
    continue;
  }

  // Порожні розділювачі — просто пропускаємо або копимо в message
  if (line.trim() === '') continue;

  // Інший текст — у message
  captureMessage.push(line.trim());
}

// Записати останній блок
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
        .map(cl => wrapCode(cl.raw, cl.highlight || interestingCodeRe.test(cl.raw)))
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

fs.writeFileSync('pretty-comment.md', body, 'utf8');
console.log('Wrote pretty-comment.md');

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
