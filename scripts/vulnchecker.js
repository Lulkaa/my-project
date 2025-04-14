
const fs = require('fs');
const path = require('path');

(async () => {
  const chalk = (await import('chalk')).default;

  const rulesPath = path.join(__dirname, '/vuln_rules/rules.json');
  const targetDir = path.join(__dirname, '../'); // cambiar si es necesario
  const excludedDirs = ['node_modules', 'scripts', 'test', '.git'];

  // Cargar reglas
  const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));

  // Función para escanear un archivo con todas las reglas
  function scanFile(filePath, rules) {
    const results = [];
    const content = fs.readFileSync(filePath, 'utf-8');

    const skipRulesByFile = {
      V01: content.includes('req.user.role') && content.match(/['"]ADMIN['"]/),
      V04: content.includes('allowedHosts'),
      V05: content.includes('execFile') && content.includes('safeCommands'),
      V06: content.includes('req.user.role') && content.includes("'CUSTOMER'"),
      V10: content.includes('req.user') && content.match(/(assignedTo|username|role)/),
    };

    rules.forEach(rule => {
      if (skipRulesByFile[rule.id]) return;

      const regex = new RegExp(rule.regex, 'gm');
      const matches = [...content.matchAll(regex)];

      matches.forEach(match => {
        const lineNumber = content.substring(0, match.index).split('\n').length;
        results.push({
          file: filePath,
          line: lineNumber,
          match: match[0].trim(),
          rule: rule.name,
          description: rule.description
        });
      });
    });

    return results;
  }

  // Recorrer archivos recursivamente, excluyendo carpetas no deseadas
  function getJsFiles(dir) {
    let files = [];
    const entries = fs.readdirSync(dir);

    entries.forEach(entry => {
      const fullPath = path.join(dir, entry);
      const stats = fs.statSync(fullPath);

      if (stats.isDirectory()) {
        if (!excludedDirs.includes(entry)) {
          files = files.concat(getJsFiles(fullPath));
        }
      } else if (entry.endsWith('.js')) {
        files.push(fullPath);
      }
    });

    return files;
  }

  // Ejecutar escaneo
  console.log(chalk.green('🔍 Escaneando código en busca de vulnerabilidades...'));

  const files = getJsFiles(targetDir);
  let totalFindings = [];

  files.forEach(file => {
    const findings = scanFile(file, rules);
    totalFindings = totalFindings.concat(findings);
  });

  // Mostrar resultados
  if (totalFindings.length > 0) {
    totalFindings.forEach(f => {
      console.log(chalk.redBright.bold(`🚨 [${f.rule}]`));
      console.log(chalk.yellow(`Archivo:`), f.file);
      console.log(chalk.cyan(`Línea ${f.line}:`), f.match);
      console.log(chalk.gray(`→ ${f.description}\n`));
    });
    console.log(chalk.bgRed.white.bold(`⚠️ Se encontraron ${totalFindings.length} posibles vulnerabilidades.`));
  } else {
    console.log(chalk.greenBright('✅ No se encontraron vulnerabilidades conocidas. Código limpio.'));
  }
})();
