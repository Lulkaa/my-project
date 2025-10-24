const fs = require("fs");
const path = "./semgrep_scan_results.txt";

if (!fs.existsSync(path)) {
  console.error(`Input file not found: ${path}`);
  process.exit(1);
}

const raw = fs.readFileSync(path, "utf8");

// Розкодувати можливі HTML-ентіті з джерела
function htmlUnescape(s) {
  return s
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}


const lines = htmlUnescape(raw).split(/\r?\n/);

// Акумулюємо знахідки
const findings = [];
let current = null;
let captureMessage = [];

// Регулярки
const fileLineRe = /^\s*([^\s].*?\.(?:js|ts|jsx|tsx|py|java|go|rb))\s*$/i;
const numberedLineRe = /^\s*(\d+┆\s*)(.*)$/;
const interestingCodeRe =
  /(const\s+regex\s*=\s*new\s+RegExp)|\b(Nested regex|vulnerable to backtracking|ReDoS)\b/i;

const ruleMarkers = [
  /^.*❯❯❱\s*(.+)$/,            // "❯❯❱ semgrep_rules.something"
  /^\s*javascript\.[\w.-]+$/,  // "javascript.lang.security...."
  /^\s*[a-z0-9_.-]+-rule\s*$/i,
  /^\s*semgrep[\w\W]*rule.*$/i,
];

// прибираємо декоративні розділювачі з message
const WALL_RE = /(?:^|\s)⋮┆[-─—–]{4,}(?:\s|$)/g;

// нормалізуємо «  .» -> «.» та зайві пробіли
function normalizeMessage(s) {
  return s
    .replace(WALL_RE, " ")           // прибрати "⋮┆------"
    .replace(/\s+\./g, ".")          // зайві пробіли перед крапкою
    .replace(/\s+/g, " ")            // злиплий текст
    .trim();
}

function normalizeNumbered(line) {
  return line.replace(/^\s+(\d+┆\s*)/, "$1").trimEnd();
}

function isRuleLine(line) {
  const t = line.trim();
  return ruleMarkers.some((re) => re.test(t));
}
function extractRule(line) {
  const m = line.match(/^.*❯❯❱\s*(.+)$/);
  if (m) return m[1].trim();
  return line.trim();
}

// Парсимо txt
for (const rawLine of lines) {
  const line = rawLine ?? "";

  // новий блок файлу
  const fileMatch = line.match(fileLineRe);
  if (fileMatch) {
    if (current) {
      current.message = normalizeMessage(captureMessage.join(" "));
      findings.push(current);
    }
    current = { file: fileMatch[1].trim(), rule: "", message: "", codeLines: [] };
    captureMessage = [];
    continue;
  }

  if (!current) continue;

  // Rule у окремому полі
  if (!current.rule && isRuleLine(line)) {
    current.rule = extractRule(line);
    continue;
  }

  // рядки коду з нумерацією
  if (numberedLineRe.test(line)) {
    current.codeLines.push(normalizeNumbered(line));
    continue;
  }

  // «цікаві» рядки коду без нумерації
  if (interestingCodeRe.test(line)) {
    current.codeLines.push(line.trim());
    continue;
  }

  // все інше — у Message
  if (line.trim() !== "") captureMessage.push(line.trim());
}

// фіналізуємо останній блок
if (current) {
  current.message = normalizeMessage(captureMessage.join(" "));
  findings.push(current);
}

// Формуємо плоскийMarkdown
const hasFindings = findings.length > 0;
const parts = [];
parts.push(`### Semgrep found ${findings.length} findings\n`);

for (const f of findings) {
  parts.push(`**File:** ${f.file}`);
  if (f.rule) parts.push(`**Rule:** ${f.rule}`);
  parts.push(`**Message:** ${f.message || "(no description)"}`);
  parts.push(`**Code strings:**`);
  if (f.codeLines.length) {
    for (const cl of f.codeLines) parts.push(cl);
  } else {
    parts.push("(none)");
  }
  parts.push(""); // розділювач між блоками
}

const output = parts.join("\n");
fs.writeFileSync("pretty-comment1.md", output, "utf8");
console.log("Wrote pretty-comment1.md");

// GITHUB_OUTPUT
try {
  const ghOut = process.env.GITHUB_OUTPUT;
  if (ghOut) {
    fs.writeFileSync(ghOut, `has_findings=${hasFindings}\n`, { flag: "a" });
  } else {
    fs.writeFileSync("./github_output.txt", `has_findings=${hasFindings}\n`, { flag: "a" });
  }
} catch (e) {
  console.warn("Could not write to GITHUB_OUTPUT:", e.message);
}

console.log(`has_findings=${hasFindings}`);




console.log(`has_findings=${hasFindings}`);

