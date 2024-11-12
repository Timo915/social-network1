const { ESLint } = require("eslint");

async function analyze(filePath) {
    const eslint = new ESLint();

    const results = await eslint.lintFiles([filePath]);
    return results.map(result => ({
        filePath: result.filePath,
        messages: result.messages,
        errorCount: result.errorCount,
        warningCount: result.warningCount
    }));
}

module.exports = { analyze };