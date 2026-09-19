const getProcesses = require('./src/collectors/processes');

getProcesses().then(processes => {
  console.log(`Found ${processes.length} processes`);
  console.log(processes.slice(0, 10)); // show top 10 by CPU usage
});