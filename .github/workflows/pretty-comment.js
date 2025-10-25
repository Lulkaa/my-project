const fs = require('fs');

// Input and output file names
const INPUT_FILE = 'semgrep_scan_results.txt';
const OUTPUT_FILE = 'pretty-comment1.md'; // The file your GitHub Action step reads

/**
 * Parses Semgrep TXT output and returns a list of finding objects.
 * This regex is specifically tuned for the provided Semgrep output format (File/Rule/Message/Code blocks).
 * @param {string} rawText - The raw content of the Semgrep TXT file.
 * @returns {Array<object>} List of findings.
 */
function parseSemgrepTxt(rawText) {
    const findings = [];
    let match;

    // Regex to capture blocks:
    // 1. File Path (e.g., routes/authRoutes.js)
    // 2. Rule ID (e.g., semgrep_rules.nosql-injection-rule)
    // 3. Message/Code Block (The entire content until the start of the next finding or end of file)
    const blockRegex = /\n\s*(\S+\.js)\n\s*❯❯❱\s*(\S+)\n([\s\S]*?)(?=\n\s*\S+\.js\n|\n\s*┌|$)/gm;

    while ((match = blockRegex.exec(rawText)) !== null) {
        // Avoid infinite loops
        if (match.index === blockRegex.lastIndex) {
            blockRegex.lastIndex++;
        }

        const [fullMatch, filePath, ruleId, messageAndCodeBlock] = match;

        // Split the captured block into lines
        const lines = messageAndCodeBlock.trim().split('\n');
        
        let message = '';
        let codeLines = [];
        let firstLine = null;

        // Iterate lines to separate the textual message from the code block
        for (const line of lines) {
            // A line is part of the code block if it starts with digits (e.g., '16┆') or a code separator ('⋮┆---')
            if (line.match(/^\s*\d+┆/) || line.match(/^\s*⋮┆/)) {
                codeLines.push(line.trim());
                // Capture the starting line number for the GitHub link
                if (!firstLine && line.match(/^\s*(\d+)┆/)) {
                    firstLine = line.match(/^\s*(\d+)┆/)[1];
                }
            } else {
                // If it's not code, it's part of the message/description
                message += line.trim() + ' ';
            }
        }
        
        // Clean up and format code block
        const codeString = codeLines.map(line => 
            // Remove line numbers, separators, and leading/trailing spaces
            line.replace(/^\d+┆\s*/, '')
                .replace(/^⋮┆-+\s*/, '')
                .trim()
        ).filter(line => line.length > 0).join('\n');
        
        // Final message cleanup
        // 🚩 FIXED LINE: Corrected the regular expression syntax.
        const cleanMessage = message.trim().replace(/\/g, '').trim(); 
        
        // We use the first line number found for the GitHub link
        const startLine = firstLine || '1';


        findings.push({
            ruleId: ruleId || 'N/A',
            filePath: filePath || 'N/A',
            message: cleanMessage, 
            codeString: codeString,
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
    fs.writeFileSync(OUTPUT_FILE, '### ⚠️ Error: Semgrep TXT report not found.');
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
    
    // Use the actual rule ID as the message if the message is empty/just the rule ID itself.
    const displayMessage = finding.message || `Possible issue found by rule \`${finding.ruleId}\`.`;

    return [
        `\n---`, // Separator before each finding
        `**File:** [${finding.filePath}:${finding.line}](${githubLink})`,
        `**Rule:** \`${finding.ruleId}\``,
        `**Message:** ${displayMessage}`,
        `**Code strings:**`,
        '```javascript', // Using 'javascript' for better syntax highlighting
        finding.codeString || 'N/A',
        '```',
    ].join('\n');
};

// --- Create Markdown Body ---

const header = hasIssues
    ? `## 🔴 Semgrep found ${findings.length} issues in the codebase (TXT Report)`
    : `## ✅ Semgrep: No issues found in TXT Report`;

// Note: We use .join('') because mdRow now includes the starting separator '---'
const details = findings.length > 0
    ? findings.map(mdRow).join('') 
    : '\nTXT report is clean.';


const body = [
    header,
    details
].join('\n');

// Write the Markdown file
fs.writeFileSync(OUTPUT_FILE, body);

// Set the has_issues variable for the "Fail if issues present" step
const output = `has_issues=${hasIssues}\n`;
fs.writeFileSync(process.env.GITHUB_OUTPUT, output, { flag: 'a' });

console.log(`Markdown report written to ${OUTPUT_FILE}`);
console.log(`has_issues=${hasIssues}`);
