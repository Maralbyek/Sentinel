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

# Processes we expect to see listening on the network side — core Windows + common dev tools
KNOWN_LISTENERS = {
    'system', 'svchost.exe', 'lsass.exe', 'services.exe', 'wininit.exe',
    'spoolsv.exe', 'code.exe', 'mdnsresponder.exe', 'onedrive.sync.service.exe'
}


def is_from_suspicious_path(path):
    if not path or path == 'Unknown':
        return False
    return any(keyword in path for keyword in SUSPICIOUS_PATH_KEYWORDS)


def is_from_trusted_path(path):
    if not path or path == 'Unknown':
        return False
    return any(path.startswith(prefix) for prefix in TRUSTED_PATH_PREFIXES)


def is_private_address(ip_str):
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False

def analyze_processes(processes):
    findings = []
    current_pid = os.getpid()

    for p in processes:
        if p['pid'] == current_pid:
            continue

        if p['path'] and '\\sentinel\\.venv\\' in p['path']:
            continue

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

    match = re.match(r'^"([^"]+)"', command)
    if match:
        return match.group(1)

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


def analyze_network_connections(connections):
    findings = []

    for conn in connections:
        if not conn['remote_address']:
            continue

        remote_ip = conn['remote_address'].rsplit(':', 1)[0]

        if is_private_address(remote_ip):
            continue

        if conn['pid'] == 0:
            continue

        if conn['process'] == 'Unknown':
            findings.append({
                'severity': 'warning',
                'title': f"Unidentified process connected to {conn['remote_address']}",
                'detail': f"A process we couldn't identify (PID {conn['pid']}) has an active connection to {conn['remote_address']}. This is unusual and worth investigating.",
                'pid': conn['pid']
            })

    return findings


def analyze_listening_ports(listening_ports):
    findings = []

    for port in listening_ports:
        addr = port['local_address']
        ip = addr.rsplit(':', 1)[0]

        if ip in ('127.0.0.1', '::1'):
            continue

        process_lower = port['process'].lower()
        if process_lower not in KNOWN_LISTENERS:
            findings.append({
                'severity': 'info',
                'title': f"{port['process']} is listening for network connections",
                'detail': f"{port['process']} is listening on {addr}, which means it can accept incoming connections from your network. This is worth knowing if it's not a program you recognize.",
                'pid': port['pid']
            })

    return findings


def analyze_security_events(events):
    findings = []

    if isinstance(events, dict) and 'error' in events:
        return findings

    for e in events:
        if e['event_id'] == 1102:
            findings.append({
                'severity': 'critical',
                'title': 'The security audit log was cleared',
                'detail': f"This happened at {e['time']}. Clearing this log is unusual and can be a sign of someone trying to hide their activity on this PC.",
            })

        if e['event_id'] == 4732:
            findings.append({
                'severity': 'warning',
                'title': 'A user was added to an administrator group',
                'detail': f"This happened at {e['time']}. Worth confirming this was done intentionally by you.",
            })

    failed_logins = [e for e in events if e['event_id'] == 4625]
    if len(failed_logins) >= 3:
        findings.append({
            'severity': 'warning',
            'title': f"{len(failed_logins)} failed login attempts detected",
            'detail': "Multiple failed login attempts were found in recent activity. If this wasn't you, it could indicate someone trying to guess your password.",
        })

    return findings

def analyze_security_status(defender_status, firewall_status, hosts_entries):
    findings = []

    # Defender checks
    if isinstance(defender_status, dict) and 'error' not in defender_status:
        if defender_status.get('real_time_protection') is False:
            findings.append({
                'severity': 'critical',
                'title': 'Windows Defender real-time protection is OFF',
                'detail': "Real-time protection is currently disabled. This leaves your PC unprotected against new threats. Turn it back on unless you intentionally disabled it (e.g., for another antivirus).",
            })
        if defender_status.get('antivirus_enabled') is False:
            findings.append({
                'severity': 'critical',
                'title': 'Antivirus protection is OFF',
                'detail': "Windows antivirus protection is currently disabled.",
            })

    # Firewall checks
    if isinstance(firewall_status, list):
        for profile in firewall_status:
            if not profile['enabled']:
                findings.append({
                    'severity': 'warning',
                    'title': f"Firewall is OFF for the {profile['profile']} network profile",
                    'detail': f"The Windows Firewall is disabled for {profile['profile']} networks, which reduces protection while connected to that type of network.",
                })

    # Hosts file checks - flag any entry, since legitimate reasons to have one are rare for a typical user
    if isinstance(hosts_entries, list) and len(hosts_entries) > 0:
        for entry in hosts_entries:
            findings.append({
                'severity': 'warning',
                'title': f"Hosts file redirects {entry['hostname']}",
                'detail': f"Your hosts file redirects {entry['hostname']} to {entry['ip']}. This overrides normal website lookups and is sometimes used by malware to silently redirect traffic. If you didn't add this yourself, it's worth investigating.",
            })

    return findings

if __name__ == '__main__':
    from src.collectors.processes import get_processes
    from src.collectors.startup import get_startup_items
    from src.collectors.network import get_network_connections, get_listening_ports
    from src.collectors.events import get_security_events
    from src.collectors.security_status import get_defender_status, get_firewall_status, get_hosts_file_entries

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

    print()

    listening = get_listening_ports()
    port_findings = analyze_listening_ports(listening)
    print(f"Open port findings: {len(port_findings)}")
    for f in port_findings:
        print(f)

    print()

    events = get_security_events()
    event_findings = analyze_security_events(events)
    print(f"Security event findings: {len(event_findings)}")
    for f in event_findings:
        print(f)

    print()

    defender = get_defender_status()
    firewall = get_firewall_status()
    hosts = get_hosts_file_entries()
    status_findings = analyze_security_status(defender, firewall, hosts)
    print(f"Security status findings: {len(status_findings)}")
    for f in status_findings:
        print(f)