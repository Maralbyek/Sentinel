import psutil
import time

def get_processes():
    processes = []
    
    # First pass: "wake up" CPU tracking for every process (returns 0.0, that's expected)
    for proc in psutil.process_iter(['pid']):
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    # Wait briefly so there's a real time window to measure CPU usage over
    time.sleep(0.5)
    
    # Second pass: now cpu_percent() gives real, meaningful numbers
    for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'exe', 'username']):
        try:
            info = proc.info
            if info['name'] == 'System Idle Process':
                continue
            processes.append({
                'pid': info['pid'],
                'name': info['name'],
                'cpu': proc.cpu_percent(interval=None),
                'memMB': round(info['memory_info'].rss / (1024 * 1024), 1) if info['memory_info'] else 0,
                'path': info['exe'] if info['exe'] else 'Unknown',
                'user': info['username'] if info['username'] else 'Unknown'
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    processes.sort(key=lambda p: p['cpu'], reverse=True)
    return processes

if __name__ == '__main__':
    procs = get_processes()
    print(f"Found {len(procs)} processes")
    for p in procs[:10]:
        print(p)