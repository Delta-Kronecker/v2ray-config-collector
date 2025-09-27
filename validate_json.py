#!/usr/bin/env python3
import json
import sys

PROTOCOLS = ('ss', 'vmess', 'vless', 'trojan')
BASE = 'config_collector/deduplicated_urls'

ok = True
for p in PROTOCOLS:
    path = f'{BASE}/{p}.json'
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, list):
            print(f'{p}.json : Array OK ({len(data)} items)')
        else:
            print(f'{p}.json : ERROR - not Array')
            ok = False
    except FileNotFoundError:
        print(f'{p}.json : File not found')
        ok = False
sys.exit(0 if ok else 1)
