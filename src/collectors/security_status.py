import subprocess
import json
import os

def get_defender_status():
    """Checks Windows Defender's real-time protection status via PowerShell."""
    try:
        result = subprocess.run(
            ['powershell', '-Command', 'Get-MpComputerStatus | ConvertTo-Json'],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(result.stdout)
        return {
            'real_time_protection': data.get('RealTimeProtectionEnabled', None),
            'antivirus_enabled': data.get('AntivirusEnabled', None),
            'antispyware_enabled': data.get('AntispywareEnabled', None),
            'last_scan': data.get('QuickScanEndTime', 'Unknown')
        }
    except Exception as e:
        return {'error': f"Could not check Defender status: {e}"}


def get_firewall_status():
    """Checks whether the Windows Firewall is enabled for each network profile."""
    try:
        result = subprocess.run(
            ['powershell', '-Command', 'Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json'],
            capture_output=True, text=True, timeout=15
        )
        data = json.loads(result.stdout)
        # PowerShell returns a single dict if there's only one profile, or a list if multiple
        if isinstance(data, dict):
            data = [data]
        return [{'profile': p['Name'], 'enabled': p['Enabled']} for p in data]
    except Exception as e:
        return {'error': f"Could not check Firewall status: {e}"}


def get_hosts_file_entries():
    """Reads the Windows hosts file and returns any active (non-comment) entries.
    Malware sometimes adds entries here to silently redirect websites."""
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    entries = []

    try:
        with open(hosts_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    entries.append({'ip': parts[0], 'hostname': parts[1]})
    except Exception as e:
        return {'error': f"Could not read hosts file: {e}"}

    return entries


if __name__ == '__main__':
    print("=== Defender Status ===")
    print(get_defender_status())

    print("\n=== Firewall Status ===")
    print(get_firewall_status())

    print("\n=== Hosts File Entries ===")
    print(get_hosts_file_entries())