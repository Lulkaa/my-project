const fs = require('fs');
const path = require('path');

// Input and output file names
const INPUT_FILE = 'semgrep_scan_results.json';
const OUTPUT_FILE = 'pretty-comment1.md'; // Matches the file in your workflow

/**
 * Converts severity level into an emoji and text for better visualization.
 * @param {string} severity - Semgrep severity level (ERROR, WARNING, INFO).
 * @returns {string} Formatted string.
 */
const formatSeverity = (severity) => {
    switch (severity.toUpperCase()) {
        case 'ERROR':
            return '🔴 **CRITICAL**';
        case 'WARNING':
            return '🟠 **MEDIUM**';
        case 'INFO':
            return '🟡 **INFO**';
        default:
            return `⚪️ **${severity.toUpperCase()}**`;
    }
};

/**
 * Generates a Markdown string for a single scan finding.
 * @param {object} finding - A single finding object from the Semgrep JSON report.
 * @returns {string} Markdown string.
 */
const mdRow = (finding) => {
    const severity = formatSeverity(finding.extra.severity);
    const message = finding.extra.message.trim();
    const ruleId = finding.extra.metadata.id || finding.check_id;
    const filePath = finding.path;
    const line = finding.start.line;
    const endLine = finding.end.line;
    
    // Link to the file and line in GitHub (works in PR context)
    // Assumes the action runs within the repo context to correctly form a relative path link.
    const githubLink = `${filePath}#L${line}`; 
    
    // Create a code block to show the vulnerable line(s)
    const codeSnippet = finding.extra.lines ? 
        `\`\`\`\n${finding.extra.lines.trim()}\n\`\`\`` :
        '';

    return [
        `### ${severity}: \`${ruleId}\``,
        `> **File:** [${filePath}:${line}-${endLine}](${githubLink})`,
        `> **Description:** ${message}`,
        codeSnippet,
        `---` // Horizontal line to separate results
    ].join('\n');
};

let rawData;
try {
    rawData = fs.readFileSync(INPUT_FILE, 'utf8');
} catch (error) {
    console.error(`Error reading file ${INPUT_FILE}: ${error.message}`);
    // Create an empty report if the file is not found
    fs.writeFileSync(OUTPUT_FILE, '### ⚠️ Error: Semgrep JSON report not found.');
    // Set has_issues to false to prevent job failure on missing file
    fs.writeFileSync(process.env.GITHUB_OUTPUT, `has_issues=false\n`, { flag: 'a' });
    process.exit(0);
}

let parsed;
try {
    parsed = JSON.parse(rawData);
} catch (error) {
    console.error(`Error parsing JSON from file ${INPUT_FILE}: ${error.message}`);
    fs.writeFileSync(OUTPUT_FILE, '### ⚠️ Error: Failed to parse Semgrep JSON.');
    fs.writeFileSync(process.env.GITHUB_OUTPUT, `has_issues=false\n`, { flag: 'a' });
    process.exit(0);
}

// Filter results. Semgrep names them "results"
const findings = Array.isArray(parsed.results) ? parsed.results : [];

// Consider only "ERROR" and "WARNING" as "Issues"
const isHighImpact = (finding) => 
    finding.extra.severity === 'ERROR' || finding.extra.severity === 'WARNING';

const hasIssues = findings.some(isHighImpact);

const highImpactFindings = findings.filter(isHighImpact);

// Sort: ERROR > WARNING > INFO
const sortedFindings = findings.sort((a, b) => {
    const severityOrder = { 'ERROR': 1, 'WARNING': 2, 'INFO': 3 };
    return severityOrder[a.extra.severity] - severityOrder[b.extra.severity];
});

// --- Create Markdown Body ---

const header = hasIssues
    ? `## 🔴 Semgrep found ${highImpactFindings.length} **Critical/Medium** vulnerabilities`
    : `## ✅ Semgrep: **No Critical/Medium** vulnerabilities found`;

const details = sortedFindings.length > 0
    ? sortedFindings.map(mdRow).join('\n')
    : 'No issues found.';


const body = [
    header,
    '',
    sortedFindings.length > 0 ? '---' : '',
    '',
    details
].join('\n');

// Write the Markdown file
fs.writeFileSync(OUTPUT_FILE, body);

// Set the has_issues variable for the "Fail if issues present" step
const output = `has_issues=${hasIssues}\n`;
fs.writeFileSync(process.env.GITHUB_OUTPUT, output, { flag: 'a' });

console.log(`Markdown report written to ${OUTPUT_FILE}`);
console.log(`has_issues=${hasIssues}`);

