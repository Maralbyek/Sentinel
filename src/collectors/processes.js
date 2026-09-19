const si = require('systeminformation');

async function getProcesses() {
  const data = await si.processes();
  
  // data.list is an array of every running process
  // Let's shape it into something clean and sorted by CPU usage
  const processes = data.list
    .map(p => ({
      pid: p.pid,
      name: p.name,
      cpu: p.cpu,
      memMB: (p.memRss / 1024).toFixed(1), // convert to MB
      path: p.path || 'Unknown',
      user: p.user || 'Unknown'
    }))
    .sort((a, b) => b.cpu - a.cpu); // highest CPU usage first

  return processes;
}

module.exports = getProcesses;