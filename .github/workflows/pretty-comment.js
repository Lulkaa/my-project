const fs = require('fs');
const path = './semgrep_scan_results.txt';

if (!fs.existsSync(path)) {
  console.error(`Input file not found: ${path}`);
  process.exit(1);
}

const raw = fs.readFileSync(path, 'utf8');
const lines = raw.split(/\r?\n/);

// Структура для збереження знахідок
const findings = [];

// Поточний стан парсера
let current = null;
let captureMessage = [];

// Регекс для виявлення рядка з назвою файлу (наприклад "routes/authRoutes.js")
// Ми вважаємо, що рядок містить шлях з розширенням (js/ts/py/java...)
const fileLineRe = /^\s*([^\s].*?\.(?:js|ts|jsx|tsx|py|java|go|rb))\s*$/i;

// Регекс для виявлення рядків коду з нумерацією як у прикладі "17┆ ..."
const numberedCodeRe = /^\s*\d+┆\s*(.*)$/;

// Регекс для виявлення конкретного рядка з new RegExp (підсвічувати)
const interestingCodeRe = /const\s+regex\s*=\s*new\s+RegExp|vulnerable to backtracking|Nested regex/i;

// Допоміжні функції щоб робити HTML-обгортки для кольорів
const red = (s) => `<span style="color:red">${escapeHtml(s)}</span>`;
const highlightYellow = (s) => `<span style="background-color: #fff59d">${escapeHtml(s)}</span>`;
const codeLineHtml = (rawLine, highlight=false) => {
  const escaped = escapeHtml(rawLine);
  return highlight ? `<div>${highlightYellow(escaped)}</div>` : `<div>${escaped}</div>`;
};

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Прохід по рядках
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];

  // Якщо знаходимо новий файл
  const fileMatch = line.match(fileLineRe);
  if (fileMatch) {
    // якщо є попередній — зберегти
    if (current) {
      current.message = captureMessage.join('\n').trim();
      findings.push(current);
    }
    // Ініціалізувати нову знахідку
    current = {
      file: fileMatch[1].trim(),
      rule: null,
      message: '',
      codeLines: []
    };
    captureMessage = [];
    continue;
  }

  if (!current) {
    // ще нічого не починалося — ігнорувати
    continue;
  }

  // Витягнути назву правила (рядок з semgrep id, наприклад "❯❯❱ semgrep_rules.nosql-injection-rule")
  const ruleMatch = line.match(/semgrep[_\-\.\w]*\S*|[a-zA-Z0-9_.-]+\.(?:detect|nosql|lang|rule)[\w\-]*/i);
  // простіше: коли бачимо стрічку з багатьма пробілами ідентифікатором (в прикладі це друга сутність після filename)
  if (!current.rule) {
    // шукаємо стрічку яка явно містить 'semgrep' або краще формат
    if (line.includes('semgrep') || line.includes('detected') || line.match(/[a-z0-9_.-]+-rule/i)) {
      current.rule = line.trim();
      continue;
    }
  }

  // Якщо рядок коду з номером
  const codeMatch = line.match(numberedCodeRe);
  if (codeMatch) {
    const code = codeMatch[1];
    const shouldHighlight = interestingCodeRe.test(code) || interestingCodeRe.test(line);
    current.codeLines.push({
      raw: code,
      highlight: shouldHighlight
    });
    continue;
  }

  // Якщо це порожній рядок - це роздільник між знахідками
  if (line.trim() === '') {
    // можливо кінець секції
    continue;
  }

  // В іншому випадку додаємо рядок до message/опису
  captureMessage.push(line.trim());
}

// Пуш останнього блоку
if (current) {
  current.message = captureMessage.join('\n').trim();
  findings.push(current);
}

// Формування markdown/html виходу
const hasFindings = findings.length > 0;

const header = hasFindings
  ? `### Semgrep found ${findings.length} findings`
  : `### Semgrep: no findings found`;

let bodyParts = [header, ''];

if (hasFindings) {
  bodyParts.push('**Details:**', '');
  for (const f of findings) {
    // Файл червоним
    const fileHtml = red(f.file);

    // Правило/рядок з ідентифікатором
    const ruleLine = f.rule ? `<div><em>${escapeHtml(f.rule.trim())}</em></div>` : '';

    // Повідомлення (короткий опис)
    const messageHtml = f.message ? `<div>${escapeHtml(f.message)}</div>` : '';

    // Коди рядки — зробимо блок <pre> з кожним рядком, підсвічуючи ті що потрібно
    let codeBlock = '';
    if (f.codeLines && f.codeLines.length > 0) {
      const inner = f.codeLines.map(cl => {
        // зберегти відступи як &nbsp; (щоб зберегти формат)
        const preserved = cl.raw.replace(/ /g, '&nbsp;');
        return cl.highlight
          ? `<div>${highlightYellow(preserved)}</div>`
          : `<div>${preserved}</div>`;
      }).join('\n');
      codeBlock = `<div style="margin-top:8px;margin-bottom:8px"><pre style="background:#f6f8fa;padding:8px;border-radius:6px;overflow:auto">${inner}</pre></div>`;
    }

    const itemHtml = `- **File:** ${fileHtml}\n  ${ruleLine ? `\n  ${ruleLine}` : ''}\n  ${messageHtml ? `\n  ${messageHtml}` : ''}\n\n${codeBlock}\n`;
    bodyParts.push(itemHtml);
  }
} else {
  bodyParts.push('');
}

const body = bodyParts.join('\n');

// Запис у файл
fs.writeFileSync('pretty-comment.md', body, 'utf8');
console.log('Wrote pretty-comment.md');

// Встановити GITHUB_OUTPUT (як у вашому оригіналі)
try {
  const ghOut = process.env.GITHUB_OUTPUT;
  if (ghOut) {
    fs.writeFileSync(ghOut, `has_findings=${hasFindings}\n`, { flag: 'a' });
  } else {
    // fallback: запис у локальний файл якщо змінної немає
    fs.writeFileSync('./github_output.txt', `has_findings=${hasFindings}\n`, { flag: 'a' });
  }
} catch (e) {
  console.warn('Could not write to GITHUB_OUTPUT:', e.message);
}

console.log(`has_findings=${hasFindings}`);
