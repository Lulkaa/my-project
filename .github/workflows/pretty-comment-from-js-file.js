const fs = require('fs');

const path = 'semgrep_scan_results.json';
let raw = fs.readFileSync(path, 'utf8');
let parsed = JSON.parse(raw);

const results = Array.isArray(parsed.results) ? parsed.results : [];

const hasFindings = results.length > 0;


const mdRow = (r) => {
  const file = r.path || '(unknown file)';
  const start = r.start?.line ?? '?';
  const end = r.end?.line ?? start;
  const message = r.extra?.message || r.message || '(no message)';
  const cweRaw = r.extra?.metadata?.cwe;
  const cwe = Array.isArray(cweRaw)
    ? cweRaw.join(', ')
    : cweRaw || 'N/A';

  return `- **File:** \`${file}\` (lines ${start}-${end})\n  - **Message:** ${message}\n  - **CWE:** ${cwe}`;
};


const header = hasFindings
  ? `### Semgrep found ${results.length} findings`
  : `### Semgrep: no findings found`;

const body = [
  header,
  '',
  hasFindings ? '**Details:**' : '',
  hasFindings ? results.map(mdRow).join('\n') : '',
  '',
].join('\n');

fs.writeFileSync('pretty-comment.md', body);

console.log(`has_findings=${hasFindings}`);
fs.writeFileSync(process.env.GITHUB_OUTPUT, `has_findings=${hasFindings}\n`, { flag: 'a' });
