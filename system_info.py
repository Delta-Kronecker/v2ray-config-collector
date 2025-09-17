import platform
import subprocess
import json
import os
import sys
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("Warning: psutil not installed. Some hardware info will be limited.")

def get_system_info():
    info = {}

    # Basic system info
    info['platform'] = {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': sys.version
    }

    # OS details via subprocess (works on Linux/Mac/Windows)
    try:
        if platform.system() == 'Linux':
            info['os_details'] = {
                'lsb_release': subprocess.getoutput('lsb_release -a') if 'lsb_release' in subprocess.getoutput('which lsb_release') else 'Not available',
                'uname': subprocess.getoutput('uname -a')
            }
        elif platform.system() == 'Darwin':  # macOS
            info['os_details'] = {
                'sw_vers': subprocess.getoutput('sw_vers'),
                'uname': subprocess.getoutput('uname -a')
            }
        elif platform.system() == 'Windows':
            info['os_details'] = {
                'systeminfo': subprocess.getoutput('systeminfo')
            }
    except Exception as e:
        info['os_details'] = f'Error: {str(e)}'

    # Hardware info (CPU, Memory, Disk)
    if HAS_PSUTIL:
        info['hardware'] = {
            'cpu': {
                'count': psutil.cpu_count(logical=True),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else 'Not available'
            },
            'memory': {
                'total': psutil.virtual_memory().total / (1024**3),  # GB
                'available': psutil.virtual_memory().available / (1024**3)
            },
            'disk': {
                'total': psutil.disk_usage('/').total / (1024**3),  # GB
                'used': psutil.disk_usage('/').used / (1024**3)
            }
        }
    else:
        info['hardware'] = 'psutil not available'

    # Installed packages (pip list)
    try:
        info['packages'] = subprocess.getoutput('pip list').split('\n')
    except:
        info['packages'] = 'pip list failed'

    # Environment variables (key ones, to avoid dumping everything)
    info['env'] = {k: v for k, v in os.environ.items() if any(x in k.lower() for x in ['path', 'home', 'user', 'github', 'actions'])}

    return info

if __name__ == '__main__':
    system_info = get_system_info()
    print(json.dumps(system_info, indent=2, default=str))
