import winreg
import os

def get_registry_startup_items():
    """Reads programs set to auto-launch via Windows Registry Run keys."""
    items = []
    
    # These are the two most common Registry locations for startup programs
    registry_locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]
    
    for hive, path in registry_locations:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    items.append({
                        'name': name,
                        'command': value,
                        'source': 'Registry (HKCU)' if hive == winreg.HKEY_CURRENT_USER else 'Registry (HKLM)'
                    })
                    i += 1
                except OSError:
                    # No more values in this key
                    break
            winreg.CloseKey(key)
        except FileNotFoundError:
            # This registry path doesn't exist on this system, skip it
            continue
    
    return items

def get_startup_folder_items():
    """Reads shortcuts placed directly in the Windows Startup folder."""
    items = []
    startup_folder = os.path.join(
        os.environ['APPDATA'],
        r'Microsoft\Windows\Start Menu\Programs\Startup'
    )
    
    if os.path.exists(startup_folder):
        for filename in os.listdir(startup_folder):
            if filename.lower() == 'desktop.ini':
                continue
            items.append({
                'name': filename,
                'command': os.path.join(startup_folder, filename),
                'source': 'Startup Folder'
            })
    
    return items

def get_startup_items():
    """Combines all startup sources into one list."""
    items = []
    items.extend(get_registry_startup_items())
    items.extend(get_startup_folder_items())
    return items

if __name__ == '__main__':
    items = get_startup_items()
    print(f"Found {len(items)} startup items")
    for item in items:
        print(item)