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

    # OS details via subprocess
    try:
        if platform.system() == 'Linux':
            info['os_details'] = {
                'lsb_release': subprocess.getoutput('lsb_release -a') if 'lsb_release' in subprocess.getoutput('which lsb_release') else 'Not available',
                'uname': subprocess.getoutput('uname -a')
            }
        elif platform.system() == 'Darwin':
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

    # Detailed hardware info (CPU, Memory, Disk)
    if HAS_PSUTIL:
        info['hardware'] = {
            'cpu': {
                'count': psutil.cpu_count(logical=True),
                'physical_count': psutil.cpu_count(logical=False),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else 'Not available',
                'per_core_usage': [psutil.cpu_percent(interval=1, percpu=True)],  # درصد استفاده هر هسته
                'load_average': psutil.getloadavg()  # بار متوسط سیستم (1, 5, 15 دقیقه)
            },
            'memory': {
                'total': psutil.virtual_memory().total / (1024**3),  # GB
                'available': psutil.virtual_memory().available / (1024**3),
                'used': psutil.virtual_memory().used / (1024**3)
            },
            'disk': {
                'total': psutil.disk_usage('/').total / (1024**3),  # GB
                'used': psutil.disk_usage('/').used / (1024**3),
                'free': psutil.disk_usage('/').free / (1024**3)
            }
        }
    else:
        info['hardware'] = 'psutil not available'

    # Uptime (only on Linux via /proc/uptime)
    try:
        if platform.system() == 'Linux':
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                info['uptime'] = {
                    'seconds': uptime_seconds,
                    'days': uptime_seconds // (24 * 3600),
                    'hours': (uptime_seconds % (24 * 3600)) // 3600,
                    'minutes': (uptime_seconds % 3600) // 60
                }
    except:
        info['uptime'] = 'Not available'

    # Installed packages
    try:
        info['packages'] = subprocess.getoutput('pip list').split('\n')
    except:
        info['packages'] = 'pip list failed'

    # Environment variables
    info['env'] = {k: v for k, v in os.environ.items() if any(x in k.lower() for x in ['path', 'home', 'user', 'github', 'actions'])}

    return info

if __name__ == '__main__':
    system_info = get_system_info()
    print(json.dumps(system_info, indent=2, default=str))
