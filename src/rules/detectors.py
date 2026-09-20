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

if __name__ == '__main__':
    from src.collectors.processes import get_processes
    procs = get_processes()
    findings = analyze_processes(procs)
    print(f"Found {len(findings)} findings:")
    for f in findings:
        print(f)