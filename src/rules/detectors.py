import os
import re
import ipaddress

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

# Common, expected ports for everyday legitimate traffic
COMMON_PORTS = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 445, 139, 135, 5353, 1900}

def analyze_network_connections(connections):
    findings = []
    
    for conn in connections:
        # Only look at connections that are actually reaching out somewhere (skip listeners/idle)
        if not conn['remote_address']:
            continue
        
        remote_port = int(conn['remote_address'].split(':')[-1])
        
        if conn['process'] == 'Unknown':
            findings.append({
                'severity': 'warning',
                'title': f"Unidentified process connected to {conn['remote_address']}",
                'detail': f"A process we couldn't identify (PID {conn['pid']}) has an active connection to {conn['remote_address']}. This is unusual and worth investigating.",
                'pid': conn['pid']
            })
        
        if remote_port not in COMMON_PORTS and remote_port > 1024:
            findings.append({
                'severity': 'info',
                'title': f"{conn['process']} is using an uncommon port",
                'detail': f"{conn['process']} is connected to {conn['remote_address']}, using port {remote_port}, which isn't one of the most common ports. This isn't necessarily bad, but worth being aware of.",
                'pid': conn['pid']
            })
    
    return findings
import ipaddress

def is_private_address(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def analyze_network_connections(connections):
    findings = []
    
    for conn in connections:
        if not conn['remote_address']:
            continue
        
        remote_ip = conn['remote_address'].rsplit(':', 1)[0]
        
        # Skip local network traffic entirely, we only care about external connections
        if is_private_address(remote_ip):
            continue
        
        if conn['process'] == 'Unknown':
            findings.append({
                'severity': 'warning',
                'title': f"Unidentified process connected to {conn['remote_address']}",
                'detail': f"A process we couldn't identify (PID {conn['pid']}) has an active connection to {conn['remote_address']}. This is unusual and worth investigating.",
                'pid': conn['pid']
            })
    
    return findings

if __name__ == '__main__':
    from src.collectors.processes import get_processes
    from src.collectors.startup import get_startup_items
    from src.collectors.network import get_network_connections

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

    print()

    connections = get_network_connections()
    network_findings = analyze_network_connections(connections)
    print(f"Network findings: {len(network_findings)}")
    for f in network_findings:
        print(f)    