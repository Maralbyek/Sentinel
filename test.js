const getProcesses = require('./src/collectors/processes');
const { analyzeProcesses } = require('./src/rules/detectors');

getProcesses().then(processes => {
  const findings = analyzeProcesses(processes);
  console.log(`Found ${findings.length} findings:`);
  console.log(findings);
});