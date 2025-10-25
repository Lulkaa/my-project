const fs = require('fs');

// Input and output file names
const INPUT_FILE = 'semgrep_scan_results.txt';
const OUTPUT_FILE = 'pretty-comment1.md'; // The file your GitHub Action step reads

/**
 * Parses Semgrep TXT output and returns a list of finding objects.
 * WARNING: Parsing TXT output is brittle and highly dependent on Semgrep's exact formatting.
 * @param {string} rawText - The raw content of the Semgrep TXT file.
 * @returns {Array<object>} List of findings.
 */
function parseSemgrepTxt(rawText) {
    const findings = [];
    let match;

    // Regex to capture blocks: Rule ID, File Path, Start Line, End Line (optional), and Code/Context
    // Example format: rule-id at path/to/file.js:14-16
    const blockRegex = /^(\S+)\s+at\s+([\w\/\.-]+):(\d+)(?:-(\d+))?\n([\s\S]*?)(?=\n\S+\s+at\s+|$)/gm;
    // Groups: 1: Rule ID, 2: File Path, 3: Start Line, 4: End Line (optional), 5: Code/Context

    while ((match = blockRegex.exec(rawText)) !== null) {
        // Avoid infinite loops for zero-width matches
        if (match.index === blockRegex.lastIndex) {
            blockRegex.lastIndex++;
        }

        const [fullMatch, ruleId, filePath, startLine, endLine, contextBlock] = match;

        // The exact message is often difficult to extract cleanly from --text, 
        // so we use the Rule ID as a placeholder/message.
        const message = `Rule ID: ${ruleId}`; 
        
        // Clean up the code context block from leading symbols ('>', '|', spaces)
        const codeString = (contextBlock || '').split('\n')
            .map(line => line.replace(/^\s*[|>]\s*/, '').trim())
            .filter(line => line.length > 0)
            .join('\n');

        findings.push({
            ruleId: ruleId || 'N/A',
            filePath: filePath || 'N/A',
            message: message, 
            codeString: codeString.trim(),
            line: startLine,
        });
    }

    return findings;
}


// --- Main Logic ---

let rawData;
try {
    rawData = fs.readFileSync(INPUT_FILE, 'utf8');
} catch (error) {
    console.error(`Error reading file ${INPUT_FILE}: ${error.message}`);
    // Create an empty report if the file is not found
    fs.writeFileSync(OUTPUT_FILE, '### ⚠️ Error: Semgrep TXT report not found.');
    // Set has_issues to false to prevent job failure on missing file
    fs.writeFileSync(process.env.GITHUB_OUTPUT, `has_issues=false\n`, { flag: 'a' });
    process.exit(0);
}

const findings = parseSemgrepTxt(rawData);

const hasIssues = findings.length > 0;

/**
 * Generates a Markdown row in the requested format (File, Rule, Message, Code strings).
 * @param {object} finding - The finding object.
 * @returns {string} Markdown string.
 */
const mdRow = (finding) => {
    // Form the link to the file for the PR
    const githubLink = `${finding.filePath}#L${finding.line}`;

    return [
        `**File:** [${finding.filePath}:${finding.line}](${githubLink})`,
        `**Rule:** \`${finding.ruleId}\``,
        `**Message:** ${finding.message}`,
        `**Code strings:**`,
        '```',
        finding.codeString || 'N/A',
        '```',
        `---` // Horizontal line to separate results
    ].join('\n');
};

// --- Create Markdown Body ---

const header = hasIssues
    ? `## ⚠️ Semgrep found ${findings.length} potential issues (TXT Report)`
    : `## ✅ Semgrep: No issues found in TXT Report`;

const details = findings.length > 0
    ? findings.map(mdRow).join('\n')
    : 'TXT report is clean.';


const body = [
    header,
    '',
    findings.length > 0 ? '---' : '', // Separator only if there are findings
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


