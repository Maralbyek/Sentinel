import psutil
import os

def get_drive_summary():
    """Overview of each drive: total, used, free space."""
    drives = []
    for part in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(part.mountpoint)
            drives.append({
                'drive': part.mountpoint,
                'total_gb': round(usage.total / (1024**3), 1),
                'used_gb': round(usage.used / (1024**3), 1),
                'free_gb': round(usage.free / (1024**3), 1),
                'percent_used': usage.percent
            })
        except PermissionError:
            # Some drives (like removable media with no disk inserted) can't be read, skip them
            continue
    return drives


def get_folder_sizes(root_path, max_depth=1):
    """Calculates the size of each top-level folder inside root_path.
    Doesn't dig infinitely deep — keeps it fast by only looking at immediate subfolders."""
    results = []

    try:
        entries = os.listdir(root_path)
    except (PermissionError, FileNotFoundError):
        return results

    for entry in entries:
        full_path = os.path.join(root_path, entry)
        if os.path.isdir(full_path):
            size = _get_dir_size(full_path)
            results.append({
                'name': entry,
                'path': full_path,
                'size_mb': round(size / (1024**2), 1)
            })

    results.sort(key=lambda f: f['size_mb'], reverse=True)
    return results


def _get_dir_size(path):
    """Walks a directory tree and sums up file sizes. Skips files/folders we can't access."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(path):
        for f in filenames:
            try:
                fp = os.path.join(dirpath, f)
                total += os.path.getsize(fp)
            except (PermissionError, FileNotFoundError, OSError):
                continue
    return total


if __name__ == '__main__':
    print("=== Drive Summary ===")
    drives = get_drive_summary()
    for d in drives:
        print(d)

    print("\n=== Top-level folder sizes in C:\\Users\\maral ===")
    user_folder = os.path.expanduser("~")
    folders = get_folder_sizes(user_folder)
    for f in folders[:10]:
        print(f)