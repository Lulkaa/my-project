const fs = require("fs");
const path = "./semgrep_scan_results.txt";

if (!fs.existsSync(path)) {
  console.error(`Input file not found: ${path}`);
  process.exit(1);
}

const raw = fs.readFileSync(path, "utf8");

/* -------------------- Utils -------------------- */

// Розкодувати можливі HTML-ентіті з джерела
function htmlUnescape(s) {
  return s
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

const lines = htmlUnescape(raw).split(/\r?\n/);

// прибираємо декоративні розділювачі з message
const WALL_RE = /(?:^|\s)⋮┆[-─—–]{4,}(?:\s|$)/g;

// нормалізуємо «  .» -> «.» та зайві пробіли
function normalizeMessage(s) {
  return s
    .replace(WALL_RE, " ")
    .replace(/\s+\./g, ".")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeNumbered(line) {
  // зберігаємо лідируючий "16┆ " тощо, але чистимо трейлінг-пробіли
  return line.replace(/^\s+(\d+┆\s*)/, "$1").trimEnd();
}

function mdEscapeInline(s) {
  // легкий ескейп для інлайнів (таблиці/заголовки не ламаємо)
  return s.replace(/[|*_`]/g, (m) => "\\" + m);
}

/* -------------------- Парсер -------------------- */

const findings = [];
let current = null;
let captureMessage = [];

const fileLineRe =
  /^\s*(?:\*\*File:\*\*\s*)?([^\s].*?\.(?:js|ts|jsx|tsx|py|java|go|rb))\s*$/i;

const numberedLineRe = /^\s*(\d+┆\s*)(.*)$/;

const interestingCodeRe =
  /(const\s+regex\s*=\s*new\s+RegExp)|\b(Nested regex|vulnerable to backtracking|ReDoS)\b/i;

const ruleMarkers = [
  /^.*❯❯❱\s*(.+)$/, // "❯❯❱ semgrep_rules.something"
  /^\s*javascript\.[\w.-]+$/, // "javascript.lang.security...."
  /^\s*[a-z0-9_.-]+-rule\s*$/i,
  /^\s*semgrep[\w\W]*rule.*$/i,
  /^\s*\*\*Rule:\*\*\s*(.+)$/i, // підтримка вже відформатованих блоків
];

function isRuleLine(line) {
  const t = line.trim();
  return ruleMarkers.some((re) => re.test(t));
}
function extractRule(line) {
  let m = line.match(/^.*❯❯❱\s*(.+)$/);
  if (m) return m[1].trim();
  m = line.match(/^\s*\*\*Rule:\*\*\s*(.+)$/i);
  if (m) return m[1].trim();
  return line.trim();
}

for (const rawLine of lines) {
  const line = rawLine ?? "";

  // новий блок файлу
  const fileMatch = line.match(fileLineRe);
  if (fileMatch) {
    if (current) {
      current.message = normalizeMessage(captureMessage.join(" "));
      findings.push(current);
    }
    current = {
      file: fileMatch[1].trim(),
      rule: "",
      message: "",
      codeLines: [],
    };
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

/* -------------------- Форматування Markdown -------------------- */

const hasFindings = findings.length > 0;

// Підрахунки для summary
const byRule = new Map();
const byFile = new Map();

for (const f of findings) {
  const rule = f.rule || "(unknown rule)";
  byRule.set(rule, (byRule.get(rule) || 0) + 1);
  byFile.set(f.file, (byFile.get(f.file) || 0) + 1);
}

function renderSummaryTable(title, map, sortDesc = true) {
  const entries = Array.from(map.entries());
  entries.sort((a, b) =>
    sortDesc ? b[1] - a[1] || a[0].localeCompare(b[0]) : a[0].localeCompare(b[0])
  );
  if (!entries.length) return "";
  const rows = entries
    .map(([k, v]) => `| ${mdEscapeInline(k)} | ${v} |`)
    .join("\n");
  return [
    `#### ${title}`,
    "",
    "| Item | Findings |",
    "|---|---:|",
    rows,
    "",
  ].join("\n");
}

function renderCodeBlock(codeLines) {
  if (!codeLines?.length) return "_(no code)_";
  // Виводимо як ```text, щоб зберегти «16┆ const ...»
  const body = codeLines.join("\n");
  return [
    "<details>",
    "<summary><strong>Show code</strong></summary>",
    "",
    "```text",
    body,
    "```",
    "",
    "</details>",
  ].join("\n");
}

const now = new Date();
const header = `# 🛡️ Semgrep Report

**Scanned:** ${now.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC")}  
**Total findings:** ${findings.length}

> This comment is auto-generated from \`semgrep_scan_results.txt\`.  
> Messages are normalized to remove decorative separators and spacing artifacts.
`;

const summary =
  renderSummaryTable("By Rule", byRule) + renderSummaryTable("By File", byFile);

const body = findings
  .map((f, idx) => {
    const ruleBadge = f.rule ? "`" + f.rule + "`" : "`(unknown rule)`";
    const message = f.message || "(no description)";
    return [
      `## ${idx + 1}. ${f.file}`,
      `**Rule:** ${ruleBadge}`,
      "",
      `> ${message}`,
      "",
      renderCodeBlock(f.codeLines),
      "",
    ].join("\n");
  })
  .join("\n");

const output = [
  header,
  hasFindings ? summary : "✅ No findings. Great job!",
  hasFindings ? "---\n" + body : "",
].join("\n");

fs.writeFileSync("pretty-comment.md", output, "utf8");
console.log("Wrote pretty-comment.md");

/* -------------------- GITHUB_OUTPUT -------------------- */
try {
  const ghOut = process.env.GITHUB_OUTPUT;
  const line = `has_findings=${hasFindings}\n`;
  if (ghOut) {
    fs.writeFileSync(ghOut, line, { flag: "a" });
  } else {
    fs.writeFileSync("./github_output.txt", line, { flag: "a" });
  }
} catch (e) {
  console.warn("Could not write to GITHUB_OUTPUT:", e.message);
}

console.log(`has_findings=${hasFindings}`);


console.log(`has_findings=${hasFindings}`);

