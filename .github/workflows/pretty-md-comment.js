const fs = require('fs');

const path = 'semgrep-scan-results.json';
let raw = fs.readFileSync(path, 'utf8');
let parsed = JSON.parse(raw);


const vulnerabilities = Array.isArray(parsed.vulnerabilities)
  ? parsed.vulnerabilities
  : [];

const wanted = new Set(['critical', 'high', 'medium']);
const vulns = vulnerabilities.filter(v =>
  wanted.has(String(v.severityWithCritical))
);

const hasIssues = vulns.length > 0;

const mdRow = (v) => {
  const sev = String(v.severityWithCritical);
  const pkg = v.packageName;
  const ver = v.version ? `@${v.version}` : '';
  const id = v.id;
  const title = v.title;
  const fix = Array.isArray(v.fixedIn) ? v.fixedIn.join(', ') : 'no fix listed';
  const depType = Array.isArray(v.from) ? (v.from.length === 2 ? 'This is direct dependency' : 'This is transitive dependency ') : 'Unknown';
  
  return `- **${sev.toUpperCase()}** \`${pkg}${ver}\` — ${title} (${id}) \n ${depType} \n Upgrade to version: ${fix}`;
};

const header = hasIssues
  ? `### Snyk found ${vulns.length} vulnerabilities`
  : `### Snyk: no medium/high/critical vulnerabilities found`;

const projectName = parsed.projectName ;

const body = [
  header,
  '',
  `**Project**: ${projectName}`,
  hasIssues ? '\n**Details:**\n' : '',
  hasIssues ? vulns.map(mdRow).join('\n') : '',
  '',
].join('\n');

fs.writeFileSync('comment.md', body);

console.log(`has_issues=${hasIssues}`);
fs.writeFileSync(process.env.GITHUB_OUTPUT , `has_issues=${hasIssues}\n`, { flag: 'a' });
