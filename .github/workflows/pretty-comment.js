const fs = require("fs");
const path = "./semgrep_scan_results.txt";

if (!fs.existsSync(path)) {
  console.error(`Input file not found: ${path}`);
  process.exit(1);
}

const raw = fs.readFileSync(path, "utf8");

function htmlUnescape(s) {
  return s
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

const lines = htmlUnescape(raw).split(/\r?\n/);

// Збір знахідок
const findings = [];
let current = null;
let captureMessage = [];

// Регулярки
const fileLineRe = /^\s*([^\s].*?\.(?:js|ts|jsx|tsx|py|java|go|rb))\s*$/i;
const numberedLineRe = /^\s*(\d+┆\s*)(.*)$/;
const interestingCodeRe =
  /(const\s+regex\s*=\s*new\s+RegExp)|\b(Nested regex|vulnerable to backtracking|ReDoS)\b/i;

// типові rule-рядки
const ruleMarkers = [
  /^.*❯❯❱\s*(.+)$/,
  /^\s*javascript\.[\w.-]+$/,
  /^\s*[a-z0-9_.-]+-rule\s*$/i,
  /^\s*semgrep[\w\W]*rule.*$/i,
];

function normalizeNumbered(line) {
  return line.replace(/^\s+(\d+┆\s*)/, "$1").trimEnd();
}
function isRuleLine(line) {
  return ruleMarkers.some((re) => re.test(line));
}
function extractRule(line) {
  const m = line.match(/^.*❯❯❱\s*(.+)$/);
  if (m) return m[1].trim();
  return line.trim();
}

// Парсинг
for (const rawLine of lines) {
  const line = rawLine ?? "";

  // новий файл
  const fileMatch = line.match(fileLineRe);
  if (fileMatch) {
    if (current) {
      current.message = captureMessage.join(" ").replace(/\s+/g, " ").trim();
      findings.push(current);
    }
    current = { file: fileMatch[1].trim(), rule: "", message: "", codeLines: [] };
    captureMessage = [];
    continue;
  }

  if (!current) continue;

  // rule
  if (!current.rule && isRuleLine(line.trim())) {
    current.rule = extractRule(line);
    continue;
  }

  // код із нумерацією
  if (numberedLineRe.test(line)) {
    current.codeLines.push(normalizeNumbered(line));
    continue;
  }

  // «цікаві» рядки без нумерації
  if (interestingCodeRe.test(line)) {
    current.codeLines.push(line.trim());
    continue;
  }

  // інше — у message
  if (line.trim() !== "") captureMessage.push(line.trim());
}

// останній блок
if (current) {
  current.message = captureMessage.join(" ").replace(/\s+/g, " ").trim();
  findings.push(current);
}

// Формування markdown
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

