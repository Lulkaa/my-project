const fs = require('fs');
const path = './semgrep_scan_results.txt';

if (!fs.existsSync(path)) {
  console.error(`Input file not found: ${path}`);
  process.exit(1);
}

const raw = fs.readFileSync(path, 'utf8');

// Невелика утиліта для заміни HTML-ентиті, якщо такі трапилися у вхідному файлі
function htmlUnescape(s) {
  return s
    .replace(/&nbsp;/g, ' ')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

const lines = htmlUnescape(raw).split(/\r?\n/);

// Збір знахідок
const findings = [];
let current = null;
let captureMessage = [];

// Регіекс для імені файлу (шлях з розширенням)
const fileLineRe = /^\s*([^\s].*?\.(?:js|ts|jsx|tsx|py|java|go|rb))\s*$/i;
// Регіекс для нумерованих рядків "17┆ some code"
const numberedLineRe = /^\s*(\d+┆\s*)(.*)$/;
// Регіекс для "цікавих" рядків (new RegExp, Nested regex, ReDoS, vulnerable to backtracking)
const interestingCodeRe = /(const\s+regex\s*=\s*new\s+RegExp)|\b(Nested regex|vulnerable to backtracking|ReDoS)\b/i;

// Нормалізуємо ведучі пробіли перед номером: "     17┆ ..." -> "17┆ ..."
function normalizeNumbered(line) {
  return line.replace(/^\s+(\d+┆\s*)/, '$1').trimEnd();
}

// Дохоплюємо знахідки
for (let i = 0; i < lines.length; i++) {
  const rawLine = lines[i];
  const line = rawLine || '';

  // Новий файл (шлях)
  const fileMatch = line.match(fileLineRe);
  if (fileMatch) {
    // зберегти попередній
    if (current) {
      current.message = captureMessage.join(' ').replace(/\s+/g, ' ').trim();
      findings.push(current);
    }
    // почати новий блок
    current = { file: fileMatch[1].trim(), message: '', codeLines: [] };
    captureMessage = [];
    continue;
  }

  if (!current) {
    // поки не зустріли файл — ігнорувати
    continue;
  }

  // Якщо рядок з нумерацією — зберігаємо (нормалізуємо пробіли)
  const numMatch = line.match(numberedLineRe);
  if (numMatch) {
    const normalized = normalizeNumbered(line);
    current.codeLines.push(normalized);
    continue;
  }

  // Якщо рядок містить цікавий патерн — зберігаємо його як окремий рядок коду
  if (interestingCodeRe.test(line)) {
    current.codeLines.push(line.trim());
    continue;
  }

  // Пусті рядки — розділювачі
  if (line.trim() === '') {
    continue;
  }

  // Інакше — частина повідомлення/опису
  captureMessage.push(line.trim());
}

// Під кінець зберегти останній блок
if (current) {
  current.message = captureMessage.join(' ').replace(/\s+/g, ' ').trim();
  findings.push(current);
}

// Формуємо markdown у потрібному простому вигляді
const hasFindings = findings.length > 0;
const header = hasFindings
  ? `### Semgrep found ${findings.length} findings`
  : `### Semgrep: no findings found`;

const parts = [header, ''];

if (hasFindings) {
  for (const f of findings) {
    parts.push(`- **File:** ${f.file}`);
    if (f.message && f.message.length > 0) {
      parts.push(`  **Message:** ${f.message}`);
    } else {
      parts.push(`  **Message:** (no description)`);
    }

    if (f.codeLines && f.codeLines.length > 0) {
      parts.push(`  **Code strings:**`);
      parts.push('  ```');
      for (const cl of f.codeLines) {
        parts.push(`  ${cl}`);
      }
      parts.push('  ```');
    } else {
      parts.push(`  **Code strings:** (none found)`);
    }

    parts.push(''); // пустий рядок між знахідками
  }
} else {
  parts.push('No findings.');
}

const output = parts.join('\n');

fs.writeFileSync('pretty-comment1.md', output, 'utf8');
console.log('Wrote pretty-comment1.md');

// Запис у GITHUB_OUTPUT
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

