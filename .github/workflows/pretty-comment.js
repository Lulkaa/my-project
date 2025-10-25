const fs = require('fs');

const txtPath = 'semgrep_scan_results.txt';
let raw = fs.readFileSync(txtPath, 'utf8');

// Parse Semgrep TXT results
const lines = raw.split('\n');
const findings = [];
let currentFinding = null;

for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  
  // Detect new file (4 spaces + file path)
  if (line.match(/^    [a-zA-Z]/) && !line.includes('❯❯❱')) {
    const filePath = line.trim();
    if (currentFinding && currentFinding.file) {
      findings.push(currentFinding);
    }
    currentFinding = {
      file: filePath,
      rule: '',
      message: '',
      codeLines: [],
    };
    continue;
  }
  
  // Detect rule (line with ❯❯❱)
  if (line.includes('❯❯❱') && currentFinding) {
    const ruleMatch = line.match(/❯❯❱\s+(.+)/);
    if (ruleMatch) {
      currentFinding.rule = ruleMatch[1].trim();
    }
    continue;
  }
  
  // Collect message (indented lines after rule)
  if (currentFinding && currentFinding.rule && !currentFinding.messageComplete) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('Details:') && !line.match(/^\s+\d+┆/)) {
      currentFinding.message += (currentFinding.message ? ' ' : '') + trimmed;
    }
    // If we hit a code line, message is complete
    if (line.match(/^\s+\d+┆/)) {
      currentFinding.messageComplete = true;
    }
  }
  
  // Collect code lines (format: number┆code)
  const codeMatch = line.match(/^\s+(\d+)┆(.+)/);
  if (codeMatch && currentFinding) {
    const lineNum = codeMatch[1];
    const code = codeMatch[2];
    currentFinding.codeLines.push(`${lineNum}: ${code}`);
  }
}

// Add last finding
if (currentFinding && currentFinding.file) {
  findings.push(currentFinding);
}

const hasIssues = findings.length > 0;

// Format MD for a single finding
const mdRow = (r) => {
  const codeBlock = r.codeLines.length > 0
    ? '\n  - **Code:**\n    ```javascript\n    ' + r.codeLines.join('\n    ') + '\n    ```'
    : '';
  
  return `- **File:** \`${r.file}\`
  - **Rule:** ${r.rule}
  - **Message:** ${r.message}${codeBlock}`;
};

// Build report
const parts = [];

if (!hasIssues) {
  parts.push('### ✅ Semgrep: no findings found');
} else {
  parts.push(`### 🔍 Semgrep found ${findings.length} finding(s)`);
  parts.push('');
  parts.push(findings.map(mdRow).join('\n\n'));
  parts.push('');
}

const body = parts.join('\n');

// Save result
fs.writeFileSync('pretty-comment1.md', body);
console.log(`has_issues=${hasIssues}`);

// Write to GITHUB_OUTPUT
if (process.env.GITHUB_OUTPUT) {
  fs.writeFileSync(
    process.env.GITHUB_OUTPUT,
    `has_issues=${hasIssues}\n`,
    { flag: 'a' }
  );
}
