#!/usr/bin/env python3
import json
import sys
import os

# مسیر کامل فایل‌ها
BASE = 'config_collector/deduplicated_urls'

PROTOCOLS = ('ss', 'vmess', 'vless', 'trojan')

print(f"Checking directory: {os.path.abspath(BASE)}")
print(f"Files in directory: {os.listdir(BASE) if os.path.exists(BASE) else 'Directory not found'}")

ok = True
for p in PROTOCOLS:
    path = os.path.join(BASE, f'{p}.json')
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            print(f'{p}.json : Array OK ({len(data)} items)')
        else:
            print(f'{p}.json : ERROR - not Array')
            ok = False
    except FileNotFoundError:
        print(f'{p}.json : File not found at {os.path.abspath(path)}')
        ok = False
    except json.JSONDecodeError as e:
        print(f'{p}.json : JSON decode error - {e}')
        ok = False
    except Exception as e:
        print(f'{p}.json : Unexpected error - {e}')
        ok = False

sys.exit(0 if ok else 1)
