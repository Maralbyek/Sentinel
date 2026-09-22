import json
import sys

from src.collectors.processes import get_processes
from src.collectors.startup import get_startup_items
from src.collectors.network import get_network_connections, get_listening_ports
from src.collectors.events import get_security_events
from src.collectors.storage import get_drive_summary, get_folder_sizes
from src.collectors.security_status import get_defender_status, get_firewall_status, get_hosts_file_entries

from src.rules.detectors import (
    analyze_processes, analyze_startup_items, analyze_network_connections,
    analyze_listening_ports, analyze_security_events, analyze_security_status
)


def run_full_scan():
    procs = get_processes()
    startup_items = get_startup_items()
    connections = get_network_connections()
    listening = get_listening_ports()
    events = get_security_events()
    drives = get_drive_summary()
    defender = get_defender_status()
    firewall = get_firewall_status()
    hosts = get_hosts_file_entries()

    all_findings = []
    all_findings += analyze_processes(procs)
    all_findings += analyze_startup_items(startup_items)
    all_findings += analyze_network_connections(connections)
    all_findings += analyze_listening_ports(listening)
    all_findings += analyze_security_events(events)
    all_findings += analyze_security_status(defender, firewall, hosts)

    return {
        'processes': procs,
        'startup_items': startup_items,
        'connections': connections,
        'listening_ports': listening,
        'drives': drives,
        'findings': all_findings
    }


if __name__ == '__main__':
    result = run_full_scan()
    print(json.dumps(result))