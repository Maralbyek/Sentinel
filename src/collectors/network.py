import psutil

def get_network_connections():
    connections = []
    
    for conn in psutil.net_connections(kind='inet'):
        try:
            # Get the process name for this connection, if we have permission to see it
            proc_name = 'Unknown'
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = 'Unknown'
            
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else 'Unknown'
            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
            
            connections.append({
                'pid': conn.pid,
                'process': proc_name,
                'local_address': local_addr,
                'remote_address': remote_addr,
                'status': conn.status,
                'protocol': 'TCP' if conn.type == 1 else 'UDP'
            })
        except Exception:
            # Some connections can be inspected mid-scan and cause odd errors, skip safely
            continue
    
    return connections

def get_listening_ports():
    """Filters all connections down to just the ones actively listening for incoming traffic."""
    all_connections = get_network_connections()
    listening = [c for c in all_connections if c['status'] == 'LISTEN']
    return listening

if __name__ == '__main__':
    conns = get_network_connections()
    print(f"Found {len(conns)} connections")
    for c in conns[:15]:
        print(c)

    print()

    listening = get_listening_ports()
    print(f"Found {len(listening)} listening ports")
    for l in listening:
        print(l)     