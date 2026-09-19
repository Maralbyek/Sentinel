// Folders considered "normal" for legitimate software to run from
const TRUSTED_PATH_PREFIXES = [
  'C:\\Program Files',
  'C:\\Program Files (x86)',
  'C:\\Windows'
];

// Folders that are common malware hiding spots
const SUSPICIOUS_PATH_KEYWORDS = [
  '\\Temp\\',
  '\\AppData\\Local\\Temp\\',
  '\\Downloads\\'
];

function isFromSuspiciousPath(path) {
  if (!path || path === 'Unknown') return false;
  return SUSPICIOUS_PATH_KEYWORDS.some(keyword => path.includes(keyword));
}

function isFromTrustedPath(path) {
  if (!path || path === 'Unknown') return false;
  return TRUSTED_PATH_PREFIXES.some(prefix => path.startsWith(prefix));
}

function analyzeProcesses(processes) {
  const findings = [];

  processes.forEach(p => {
    if (isFromSuspiciousPath(p.path)) {
      findings.push({
        severity: 'warning',
        title: `${p.name} is running from a suspicious location`,
        detail: `This process is running from ${p.path}, which is a common location for temporary or unwanted software. Legitimate programs usually run from Program Files.`,
        pid: p.pid
      });
    }

    if (p.cpu > 50 && p.name != 'System Idle Process') {
      findings.push({
        severity: 'info',
        title: `${p.name} is using high CPU`,
        detail: `This process is currently using ${p.cpu.toFixed(1)}% of your CPU. If your PC feels slow, this could be why.`,
        pid: p.pid
      });
    }
  });

  return findings;
}

module.exports = { analyzeProcesses };