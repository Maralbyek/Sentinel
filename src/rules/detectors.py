import os
import re

# Folders considered "normal" for legitimate software to run from
TRUSTED_PATH_PREFIXES = [
    'C:\\Program Files',
    'C:\\Program Files (x86)',
    'C:\\Windows'
]

# Folders that are common malware hiding spots
SUSPICIOUS_PATH_KEYWORDS = [
    '\\Temp\\',
    '\\AppData\\Local\\Temp\\',
    '\\Downloads\\'
]

def is_from_suspicious_path(path):
    if not path or path == 'Unknown':
        return False
    return any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS)

def is_from_trusted_path(path):
    if not path or path == 'Unknown':
        return False
    return any(path.startswith(prefix) for prefix in TRUSTED_PATH_PREFIXES)

def analyze_processes(processes):
    findings = []

    for p in processes:
        if is_from_suspicious_path(p['path']):
            findings.append({
                'severity': 'warning',
                'title': f"{p['name']} is running from a suspicious location",
                'detail': f"This process is running from {p['path']}, which is a common location for temporary or unwanted software. Legitimate programs usually run from Program Files.",
                'pid': p['pid']
            })

        if p['cpu'] > 50:
            findings.append({
                'severity': 'info',
                'title': f"{p['name']} is using high CPU",
                'detail': f"This process is currently using {p['cpu']:.1f}% of your CPU. If your PC feels slow, this could be why.",
                'pid': p['pid']
            })

    return findings

def extract_exe_path(command):
    """Pulls the actual executable path out of a startup command string,
    which may include quotes and extra arguments."""
    command = command.strip()
    command = os.path.expandvars(command)
    
    # If the path is quoted, extract just what's inside the quotes
    match = re.match(r'^"([^"]+)"', command)
    if match:
        return match.group(1)
    
    # Otherwise, find the first .exe occurrence and cut the string there,
    # even if there's no space or quote right after it
    match = re.search(r'^(.*?\.exe)', command, re.IGNORECASE)
    if match:
        return match.group(1)
    
    return command

def analyze_startup_items(items):
    findings = []
    
    for item in items:
        exe_path = extract_exe_path(item['command'])
        
        if is_from_suspicious_path(exe_path):
            findings.append({
                'severity': 'warning',
                'title': f"{item['name']} auto-starts from a suspicious location",
                'detail': f"This program launches automatically when Windows starts, from {exe_path}, a location commonly used by temporary or unwanted software.",
                'source': item['source']
            })
        
        if exe_path and exe_path != 'Unknown' and not os.path.exists(exe_path):
            findings.append({
                'severity': 'warning',
                'title': f"{item['name']} points to a missing file",
                'detail': f"This startup entry references {exe_path}, which no longer exists on this PC. This can be leftover from uninstalled software, or a sign of a broken/tampered entry.",
                'source': item['source']
            })
    
    return findings

if __name__ == '__main__':
    from src.collectors.processes import get_processes
    from src.collectors.startup import get_startup_items
    
    procs = get_processes()
    findings = analyze_processes(procs)
    print(f"Process findings: {len(findings)}")
    for f in findings:
        print(f)
    
    print()
    
    startup_items = get_startup_items()
    startup_findings = analyze_startup_items(startup_items)
    print(f"Startup findings: {len(startup_findings)}")
    for f in startup_findings:
        print(f)