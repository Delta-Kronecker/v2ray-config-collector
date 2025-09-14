import base64
import urllib.parse
import re
import json
from typing import Dict, List, Tuple, Optional, Union
import os

def decode_base64_safe(s: str) -> Optional[str]:
    if not s:
        return None

    try:
        s_cleaned = s.strip()
        # Remove common trailing characters that break base64
        s_cleaned = re.sub(r'[⚡️\s]+$', '', s_cleaned)
        s_cleaned = s_cleaned.rstrip('=')

        s_standard = s_cleaned.replace('-', '+').replace('_', '/')
        missing_padding = len(s_standard) % 4
        if missing_padding:
            s_standard += '=' * (4 - missing_padding)
        return base64.b64decode(s_standard).decode('utf-8', errors='ignore')
    except:
        try:
            s_clean = re.sub(r'[⚡️\s]+$', '', s.strip())
            return base64.urlsafe_b64decode(s_clean + '==').decode('utf-8', errors='ignore')
        except:
            try:
                s_clean = re.sub(r'[⚡️\s]+$', '', s.strip())
                return base64.b64decode(s_clean).decode('utf-8', errors='ignore')
            except:
                return None


def encode_base64_userinfo(method: str, password: str) -> str:
    userinfo = f"{method}:{password}"
    return base64.urlsafe_b64encode(userinfo.encode('utf-8')).decode('utf-8').rstrip('=')


def encode_base64_safe(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode('utf-8')).decode('utf-8').rstrip('=')


def clean_hostname(hostname: str) -> str:
    hostname = hostname.strip()
    # Handle IPv6 addresses wrapped in brackets
    if hostname.startswith('[') and hostname.endswith(']'):
        return hostname[1:-1]
    # Remove protocol prefixes
    if hostname.startswith('http://'):
        hostname = hostname[7:]
    if hostname.startswith('https://'):
        hostname = hostname[8:]
    # Extract hostname from URL paths
    if '/' in hostname:
        hostname = hostname.split('/')[0]
    if hostname.startswith('.'):
        hostname = hostname[1:]
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    return hostname


def extract_tag_from_config(config: str) -> Tuple[str, str]:
    if '#' in config:
        config_part, tag = config.rsplit('#', 1)
        tag = urllib.parse.unquote(tag).strip()
        return config_part, tag
    return config, ''


def is_valid_ipv4(ip: str) -> bool:
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except:
        return False


def is_valid_ipv6(ip: str) -> bool:
    try:
        # Simple IPv6 validation
        if '::' in ip:
            parts = ip.split('::')
            if len(parts) != 2:
                return False
            # Check parts before and after ::
            for part in parts:
                if part and not all(len(segment) <= 4 and all(c in '0123456789abcdefABCDEF' for c in segment)
                                    for segment in part.split(':')):
                    return False
            return True
        else:
            segments = ip.split(':')
            return len(segments) == 8 and all(
                len(seg) <= 4 and all(c in '0123456789abcdefABCDEF' for c in seg) for seg in segments)
    except:
        return False


def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 255:
        return False
    if hostname in ['.com', 'localhost', 'Free'] or hostname.startswith('.com:'):
        return False
    if hostname.startswith('http://') or hostname.startswith('https://'):
        return False
    if 'github.com' in hostname.lower() or 'project' in hostname.lower():
        return False
    # Allow common test domains but block obvious fake ones
    if hostname.lower() in ['www.speedtest.net', 'speedtest.net']:
        return True
    if is_valid_ipv4(hostname) or is_valid_ipv6(hostname):
        return True

    # Very flexible hostname validation
    # Standard domain format
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
                hostname):
        return True
    # Allow domains with underscores and dots
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]*[a-zA-Z0-9]$', hostname) and len(hostname) <= 253:
        return True
    # Allow subdomains and complex domain names
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]*\.[a-zA-Z]{2,}$', hostname) and len(hostname) <= 253:
        return True
    # Allow single word hostnames (for test domains)
    if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-_.]*$', hostname) and len(hostname) >= 3 and len(hostname) <= 63:
        return True
    return False


def is_valid_uuid(uuid_str: str) -> bool:
    if not uuid_str:
        return False
    if uuid_str.lower() in ['free', 'test']:
        return False
    # Standard UUID format (36 characters)
    if len(uuid_str) == 36:
        pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        if re.match(pattern, uuid_str):
            return True
    # UUID without dashes (32 characters)
    if len(uuid_str) == 32:
        pattern = r'^[0-9a-fA-F]{32}$'
        if re.match(pattern, uuid_str):
            return True
    # Very flexible UUID validation for custom formats like "Parsashonam-306"
    if len(uuid_str) >= 4 and len(uuid_str) <= 64:
        # Allow alphanumeric characters, dashes, and underscores
        if re.match(r'^[a-zA-Z0-9\-_]+$', uuid_str) and not uuid_str.isdigit():
            return True
    return False


def parse_query_string(query: str) -> Dict[str, str]:
    params = {}
    if not query:
        return params

    # Handle query strings that might have issues with URL encoding
    for param in query.split('&'):
        if '=' in param:
            key, value = param.split('=', 1)
            try:
                decoded_key = urllib.parse.unquote(key).strip()
                decoded_value = urllib.parse.unquote(value).strip()

                # Handle empty values
                if not decoded_value:
                    decoded_value = ''

                # Limit excessively long parameter values to prevent issues
                if len(decoded_value) > 2048:
                    decoded_value = decoded_value[:2048]

                # Clean up common issues in values
                if decoded_value.endswith('/') and len(decoded_value) > 1:
                    decoded_value = decoded_value.rstrip('/')

                params[decoded_key] = decoded_value
            except:
                # If URL decoding fails, use original values but clean them
                clean_key = key.strip()
                clean_value = value.strip() if value else ''
                params[clean_key] = clean_value
        else:
            try:
                decoded_param = urllib.parse.unquote(param).strip()
                if decoded_param:
                    params[decoded_param] = ''
            except:
                clean_param = param.strip()
                if clean_param:
                    params[clean_param] = ''

    return params


def parse_shadowsocks_config(config: str) -> Optional[Dict]:
    """Parse Shadowsocks configuration strings."""
    if not config.startswith('ss://'):
        return None

    config = config[5:]
    config_part, tag = extract_tag_from_config(config)

    # Handle different SS formats
    if '@' in config_part:
        # Format: ss://method:password@hostname:port or ss://base64(method:password)@hostname:port
        auth_part, server_part = config_part.split('@', 1)

        # Try to decode auth_part as base64 first
        decoded_auth = decode_base64_safe(auth_part)
        if decoded_auth and ':' in decoded_auth:
            method, password = decoded_auth.split(':', 1)
        elif ':' in auth_part:
            method, password = auth_part.split(':', 1)
        else:
            decoded = decode_base64_safe(auth_part)
            if decoded and ':' in decoded:
                method, password = decoded.split(':', 1)
            else:
                method = 'aes-256-gcm'
                password = auth_part

        # Parse server part
        if '?' in server_part:
            server_addr, query_part = server_part.split('?', 1)
        else:
            server_addr = server_part
            query_part = ''

    else:
        # Format: ss://base64(method:password:hostname:port)
        decoded = decode_base64_safe(config_part)
        if not decoded:
            return None

        # Check if it contains @ after decoding
        if '@' in decoded:
            auth_part, server_part = decoded.split('@', 1)
            if ':' in auth_part:
                method, password = auth_part.split(':', 1)
            else:
                return None
            server_addr = server_part
            query_part = ''
        else:
            # Legacy format: method:password:hostname:port
            parts = decoded.split(':')
            if len(parts) < 4:
                return None
            method = parts[0]
            password = parts[1]
            # Handle IPv6 addresses
            if len(parts) > 4:
                hostname = ':'.join(parts[2:-1])
                port_str = parts[-1]
            else:
                hostname = parts[2]
                port_str = parts[3]
            server_addr = f"{hostname}:{port_str}"
            query_part = ''

    # Parse hostname and port from server_addr
    if '[' in server_addr and ']:' in server_addr:
        # IPv6 address format [::1]:8080
        ipv6_end = server_addr.rfind(']:')
        hostname = server_addr[1:ipv6_end]
        port_str = server_addr[ipv6_end + 2:]
    elif ':' in server_addr:
        hostname, port_str = server_addr.rsplit(':', 1)
    else:
        return None

    # Remove any path from port (e.g., "443/" -> "443")
    if '/' in port_str:
        port_str = port_str.split('/')[0]

    hostname = clean_hostname(hostname)
    if not is_valid_hostname(hostname):
        return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    params = parse_query_string(query_part)

    return {
        'protocol': 'ss',
        'method': method,
        'password': password,
        'hostname': hostname,
        'port': port,
        'plugin': params.get('plugin', ''),
        'plugin_opts': params.get('plugin-opts', ''),
        'tag': tag
    }


def parse_vmess_config(config: str) -> Optional[Dict]:
    if not config.startswith('vmess://'):
        return None

    config = config[8:]
    config_part, tag = extract_tag_from_config(config)

    decoded = decode_base64_safe(config_part)
    if not decoded:
        return None

    try:
        data = json.loads(decoded)
        if not isinstance(data, dict):
            return None

        hostname = clean_hostname(str(data.get('add', '')))
        if not hostname or not is_valid_hostname(hostname):
            return None

        uuid = str(data.get('id', ''))
        if not is_valid_uuid(uuid):
            return None

        try:
            port = int(data.get('port', 0))
            if not (1 <= port <= 65535):
                return None
        except:
            return None

        return {
            'protocol': 'vmess',
            'uuid': uuid,
            'hostname': hostname,
            'port': port,
            'alterId': data.get('aid', 0),
            'security': data.get('scy', 'auto'),
            'network': data.get('net', 'tcp'),
            'type': data.get('type', 'none'),
            'host': data.get('host', ''),
            'path': data.get('path', ''),
            'tls': data.get('tls', ''),
            'sni': data.get('sni', ''),
            'alpn': data.get('alpn', ''),
            'tag': tag or data.get('ps', '')
        }
    except:
        return None


def parse_vless_config(config: str) -> Optional[Dict]:
    if not config.startswith('vless://'):
        return None

    config = config[8:]
    config_part, tag = extract_tag_from_config(config)

    if '@' not in config_part:
        return None

    uuid_part, server_part = config_part.split('@', 1)

    if not uuid_part or len(uuid_part) < 4:
        return None

    if not is_valid_uuid(uuid_part):
        return None

    if '?' in server_part:
        server_addr, query_part = server_part.split('?', 1)
    else:
        server_addr = server_part
        query_part = ''

    # Handle IPv6 addresses
    if '[' in server_addr and ']:' in server_addr:
        ipv6_end = server_addr.rfind(']:')
        hostname = server_addr[1:ipv6_end]
        port_str = server_addr[ipv6_end + 2:]
    elif ':' in server_addr:
        hostname, port_str = server_addr.rsplit(':', 1)
    else:
        return None

    # Clean port string (remove trailing slash, etc.)
    if '/' in port_str:
        port_str = port_str.split('/')[0]
    port_str = port_str.strip()

    hostname = clean_hostname(hostname)

    if not is_valid_hostname(hostname):
        return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    params = parse_query_string(query_part)

    # Handle empty security parameter
    security = params.get('security', 'none')
    if not security or security.strip() == '':
        security = 'none'

    return {
        'protocol': 'vless',
        'uuid': uuid_part,
        'hostname': hostname,
        'port': port,
        'encryption': params.get('encryption', 'none'),
        'security': security,
        'sni': params.get('sni', ''),
        'alpn': params.get('alpn', ''),
        'fp': params.get('fp', ''),
        'type': params.get('type', 'tcp'),
        'host': params.get('host', ''),
        'path': params.get('path', ''),
        'serviceName': params.get('serviceName', ''),
        'headerType': params.get('headerType', ''),
        'mode': params.get('mode', ''),
        'flow': params.get('flow', ''),
        # Reality protocol parameters
        'pbk': params.get('pbk', ''),
        'sid': params.get('sid', ''),
        'spx': params.get('spx', ''),
        'pqv': params.get('pqv', ''),
        # gRPC parameters
        'authority': params.get('authority', ''),
        # Additional parameters
        'ed': params.get('ed', ''),
        'tag': tag
    }


def parse_trojan_config(config: str) -> Optional[Dict]:
    if not config.startswith('trojan://'):
        return None

    config = config[9:]
    config_part, tag = extract_tag_from_config(config)

    if '@' not in config_part:
        return None

    # Handle multiple @ symbols by finding the last one
    at_pos = config_part.rfind('@')
    password_part = config_part[:at_pos]
    server_part = config_part[at_pos + 1:]

    # Check for valid password
    if not password_part or len(password_part) < 1:
        return None

    # Handle cases like "TestingServer@@@" where password contains extra @
    password_part = password_part.rstrip('@')
    # Also handle passwords that start with @
    password_part = password_part.lstrip('@')
    if not password_part:
        return None

    if '?' in server_part:
        server_addr, query_part = server_part.split('?', 1)
    else:
        server_addr = server_part
        query_part = ''

    # Handle IPv6 addresses
    if '[' in server_addr and ']:' in server_addr:
        ipv6_end = server_addr.rfind(']:')
        hostname = server_addr[1:ipv6_end]
        port_str = server_addr[ipv6_end + 2:]
    elif ':' in server_addr:
        hostname, port_str = server_addr.rsplit(':', 1)
    else:
        return None

    # Remove any path from port (e.g., "443/" -> "443")
    if '/' in port_str:
        port_str = port_str.split('/')[0]

    hostname = clean_hostname(hostname)

    if not is_valid_hostname(hostname):
        return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    params = parse_query_string(query_part)

    return {
        'protocol': 'trojan',
        'password': password_part,
        'hostname': hostname,
        'port': port,
        'security': params.get('security', 'tls'),
        'sni': params.get('sni', ''),
        'alpn': params.get('alpn', ''),
        'fp': params.get('fp', ''),
        'type': params.get('type', 'tcp'),
        'host': params.get('host', ''),
        'path': params.get('path', ''),
        'serviceName': params.get('serviceName', ''),
        'allowInsecure': params.get('allowInsecure', ''),
        'tag': tag
    }


def parse_ssr_config(config: str) -> Optional[Dict]:
    if not config.startswith('ssr://'):
        return None

    config = config[6:]
    config_part, tag = extract_tag_from_config(config)

    decoded = decode_base64_safe(config_part)
    if not decoded:
        return None

    parts = decoded.split('/')
    if len(parts) < 1:
        return None

    main_part = parts[0]
    query_part = parts[1] if len(parts) > 1 else ''

    components = main_part.split(':')
    if len(components) != 6:
        return None

    server, port_str, protocol, method, obfs, password_b64 = components

    hostname = clean_hostname(server)
    if not is_valid_hostname(hostname):
        return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    password = decode_base64_safe(password_b64)
    if not password:
        password = password_b64

    params = {}
    if query_part.startswith('?'):
        query_part = query_part[1:]

    for param in query_part.split('&'):
        if '=' in param:
            key, value = param.split('=', 1)
            decoded_value = decode_base64_safe(value)
            params[key] = decoded_value if decoded_value else value

    return {
        'protocol': 'ssr',
        'hostname': hostname,
        'port': port,
        'password': password,
        'method': method,
        'ssr_protocol': protocol,
        'obfs': obfs,
        'obfsparam': params.get('obfsparam', ''),
        'protoparam': params.get('protoparam', ''),
        'remarks': params.get('remarks', tag),
        'group': params.get('group', ''),
        'tag': tag
    }


def parse_hysteria_config(config: str) -> Optional[Dict]:
    if not config.startswith('hysteria://') and not config.startswith('hy://'):
        return None

    if config.startswith('hysteria://'):
        config = config[11:]
        protocol_name = 'hysteria'
    else:
        config = config[5:]
        protocol_name = 'hy'

    config_part, tag = extract_tag_from_config(config)

    if '?' in config_part:
        server_part, query_part = config_part.split('?', 1)
    else:
        server_part = config_part
        query_part = ''

    # Handle IPv6 addresses
    if '[' in server_part and ']:' in server_part:
        ipv6_end = server_part.rfind(']:')
        hostname = server_part[1:ipv6_end]
        port_str = server_part[ipv6_end + 2:]
    elif ':' in server_part:
        hostname, port_str = server_part.rsplit(':', 1)
    else:
        return None

    hostname = clean_hostname(hostname)

    if not is_valid_hostname(hostname):
        return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    params = parse_query_string(query_part)

    return {
        'protocol': protocol_name,
        'hostname': hostname,
        'port': port,
        'auth': params.get('auth', ''),
        'peer': params.get('peer', ''),
        'insecure': params.get('insecure', '0'),
        'upmbps': params.get('upmbps', ''),
        'downmbps': params.get('downmbps', ''),
        'alpn': params.get('alpn', ''),
        'obfs': params.get('obfs', ''),
        'tag': tag
    }


def parse_hysteria2_config(config: str) -> Optional[Dict]:
    if not config.startswith('hysteria2://') and not config.startswith('hy2://'):
        return None

    if config.startswith('hysteria2://'):
        config = config[12:]
    else:
        config = config[6:]

    config_part, tag = extract_tag_from_config(config)

    if '@' not in config_part:
        return None

    auth_part, server_part = config_part.split('@', 1)

    if '/' in server_part:
        server_addr, path_query = server_part.split('/', 1)
    else:
        server_addr = server_part
        path_query = ''

    if '?' in path_query:
        path, query_part = path_query.split('?', 1)
    else:
        path = path_query
        query_part = ''

    # Handle IPv6 addresses
    if '[' in server_addr and ']:' in server_addr:
        ipv6_end = server_addr.rfind(']:')
        hostname = server_addr[1:ipv6_end]
        port_str = server_addr[ipv6_end + 2:]
    elif ':' in server_addr:
        hostname, port_str = server_addr.rsplit(':', 1)
    else:
        return None

    hostname = clean_hostname(hostname)

    if not is_valid_hostname(hostname):
        return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    params = parse_query_string(query_part)

    return {
        'protocol': 'hysteria2',
        'hostname': hostname,
        'port': port,
        'auth': auth_part,
        'sni': params.get('sni', ''),
        'insecure': params.get('insecure', '0'),
        'obfs': params.get('obfs', ''),
        'obfs-password': params.get('obfs-password', ''),
        'pinSHA256': params.get('pinSHA256', ''),
        'security': params.get('security', ''),
        'mport': params.get('mport', ''),
        'tag': tag
    }


def parse_tuic_config(config: str) -> Optional[Dict]:
    if not config.startswith('tuic://'):
        return None

    config = config[7:]
    config_part, tag = extract_tag_from_config(config)

    if '@' not in config_part:
        return None

    userinfo_part, server_part = config_part.split('@', 1)

    if ':' not in userinfo_part:
        return None

    uuid_part, password_part = userinfo_part.split(':', 1)

    if not uuid_part or len(uuid_part) < 4:
        return None

    if '?' in server_part:
        server_addr, query_part = server_part.split('?', 1)
    else:
        server_addr = server_part
        query_part = ''

    # Handle IPv6 addresses
    if '[' in server_addr and ']:' in server_addr:
        ipv6_end = server_addr.rfind(']:')
        hostname = server_addr[1:ipv6_end]
        port_str = server_addr[ipv6_end + 2:]
    elif ':' in server_addr:
        hostname, port_str = server_addr.rsplit(':', 1)
    else:
        return None

    hostname = clean_hostname(hostname)

    if not is_valid_hostname(hostname):
        return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
    except:
        return None

    params = parse_query_string(query_part)

    return {
        'protocol': 'tuic',
        'uuid': uuid_part,
        'password': password_part,
        'hostname': hostname,
        'port': port,
        'congestion_control': params.get('congestion_control', 'bbr'),
        'udp_relay_mode': params.get('udp_relay_mode', 'native'),
        'alpn': params.get('alpn', 'h3'),
        'allow_insecure': params.get('allow_insecure', '0'),
        'sni': params.get('sni', ''),
        'tag': tag
    }


def format_shadowsocks_to_standard(config: Dict) -> str:
    """Format Shadowsocks config to standard format."""
    method = config['method']
    password = config['password']
    hostname = config['hostname']
    port = config['port']

    # Create the userinfo part (method:password)
    userinfo = f"{method}:{password}"
    userinfo_b64 = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip('=')

    # Handle IPv6 addresses
    if is_valid_ipv6(hostname):
        url = f"ss://{userinfo_b64}@[{hostname}]:{port}"
    else:
        url = f"ss://{userinfo_b64}@{hostname}:{port}"

    params = []
    if config.get('plugin'):
        params.append(f"plugin={urllib.parse.quote(config['plugin'])}")
    if config.get('plugin_opts'):
        params.append(f"plugin-opts={urllib.parse.quote(config['plugin_opts'])}")

    if params:
        url += f"?{'&'.join(params)}"

    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def format_vmess_to_standard(config: Dict) -> str:
    vmess_data = {
        'v': '2',
        'ps': config.get('tag', ''),
        'add': config['hostname'],
        'port': str(config['port']),
        'id': config.get('uuid', ''),
        'aid': str(config.get('alterId', 0)),
        'scy': config.get('security', 'auto'),
        'net': config.get('network', 'tcp'),
        'type': config.get('type', 'none'),
        'host': config.get('host', ''),
        'path': config.get('path', ''),
        'tls': config.get('tls', ''),
        'sni': config.get('sni', ''),
        'alpn': config.get('alpn', '')
    }

    json_str = json.dumps(vmess_data, separators=(',', ':'))
    encoded = encode_base64_safe(json_str)

    url = f"vmess://{encoded}"
    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def format_vless_to_standard(config: Dict) -> str:
    hostname = config['hostname']
    if is_valid_ipv6(hostname):
        url = f"vless://{config['uuid']}@[{hostname}]:{config['port']}"
    else:
        url = f"vless://{config['uuid']}@{hostname}:{config['port']}"

    params = []
    if config.get('encryption', 'none') != 'none':
        params.append(f"encryption={config['encryption']}")
    if config.get('security', 'none') != 'none':
        params.append(f"security={config['security']}")
    if config.get('sni'):
        params.append(f"sni={config['sni']}")
    if config.get('alpn'):
        params.append(f"alpn={config['alpn']}")
    if config.get('fp'):
        params.append(f"fp={config['fp']}")
    if config.get('type', 'tcp') != 'tcp':
        params.append(f"type={config['type']}")
    if config.get('host'):
        params.append(f"host={config['host']}")
    if config.get('path'):
        params.append(f"path={urllib.parse.quote(config['path'])}")
    if config.get('serviceName'):
        params.append(f"serviceName={config['serviceName']}")
    if config.get('headerType'):
        params.append(f"headerType={config['headerType']}")
    if config.get('mode'):
        params.append(f"mode={config['mode']}")
    if config.get('flow'):
        params.append(f"flow={config['flow']}")
    # Reality protocol parameters
    if config.get('pbk'):
        params.append(f"pbk={config['pbk']}")
    if config.get('sid'):
        params.append(f"sid={config['sid']}")
    if config.get('spx'):
        params.append(f"spx={config['spx']}")
    if config.get('pqv'):
        params.append(f"pqv={config['pqv']}")
    # gRPC parameters
    if config.get('authority'):
        params.append(f"authority={config['authority']}")
    # Additional parameters
    if config.get('ed'):
        params.append(f"ed={config['ed']}")

    if params:
        url += f"?{'&'.join(params)}"

    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def format_trojan_to_standard(config: Dict) -> str:
    hostname = config['hostname']
    if is_valid_ipv6(hostname):
        url = f"trojan://{config['password']}@[{hostname}]:{config['port']}"
    else:
        url = f"trojan://{config['password']}@{hostname}:{config['port']}"

    params = []
    if config.get('security', 'tls') != 'tls':
        params.append(f"security={config['security']}")
    if config.get('sni'):
        params.append(f"sni={config['sni']}")
    if config.get('alpn'):
        params.append(f"alpn={config['alpn']}")
    if config.get('fp'):
        params.append(f"fp={config['fp']}")
    if config.get('type', 'tcp') != 'tcp':
        params.append(f"type={config['type']}")
    if config.get('host'):
        params.append(f"host={config['host']}")
    if config.get('path'):
        params.append(f"path={urllib.parse.quote(config['path'])}")
    if config.get('serviceName'):
        params.append(f"serviceName={config['serviceName']}")
    if config.get('allowInsecure'):
        params.append(f"allowInsecure={config['allowInsecure']}")

    if params:
        url += f"?{'&'.join(params)}"

    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def format_ssr_to_standard(config: Dict) -> str:
    password_b64 = encode_base64_safe(config['password'])
    main_part = f"{config['hostname']}:{config['port']}:{config['ssr_protocol']}:{config['method']}:{config['obfs']}:{password_b64}"

    params = []
    if config.get('obfsparam'):
        params.append(f"obfsparam={encode_base64_safe(config['obfsparam'])}")
    if config.get('protoparam'):
        params.append(f"protoparam={encode_base64_safe(config['protoparam'])}")
    if config.get('remarks'):
        params.append(f"remarks={encode_base64_safe(config['remarks'])}")
    if config.get('group'):
        params.append(f"group={encode_base64_safe(config['group'])}")

    if params:
        main_part += f"/?{'&'.join(params)}"

    encoded = encode_base64_safe(main_part)
    url = f"ssr://{encoded}"

    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def format_hysteria_to_standard(config: Dict) -> str:
    protocol_prefix = 'hysteria://' if config['protocol'] == 'hysteria' else 'hy://'
    hostname = config['hostname']
    if is_valid_ipv6(hostname):
        url = f"{protocol_prefix}[{hostname}]:{config['port']}"
    else:
        url = f"{protocol_prefix}{hostname}:{config['port']}"

    params = []
    if config.get('auth'):
        params.append(f"auth={config['auth']}")
    if config.get('peer'):
        params.append(f"peer={config['peer']}")
    if config.get('insecure', '0') != '0':
        params.append(f"insecure={config['insecure']}")
    if config.get('upmbps'):
        params.append(f"upmbps={config['upmbps']}")
    if config.get('downmbps'):
        params.append(f"downmbps={config['downmbps']}")
    if config.get('alpn'):
        params.append(f"alpn={config['alpn']}")
    if config.get('obfs'):
        params.append(f"obfs={config['obfs']}")

    if params:
        url += f"?{'&'.join(params)}"

    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def format_hysteria2_to_standard(config: Dict) -> str:
    hostname = config['hostname']
    if is_valid_ipv6(hostname):
        url = f"hysteria2://{config['auth']}@[{hostname}]:{config['port']}/"
    else:
        url = f"hysteria2://{config['auth']}@{hostname}:{config['port']}/"

    params = []
    if config.get('sni'):
        params.append(f"sni={config['sni']}")
    if config.get('insecure', '0') != '0':
        params.append(f"insecure={config['insecure']}")
    if config.get('obfs'):
        params.append(f"obfs={config['obfs']}")
    if config.get('obfs-password'):
        params.append(f"obfs-password={config['obfs-password']}")
    if config.get('pinSHA256'):
        params.append(f"pinSHA256={config['pinSHA256']}")
    if config.get('security'):
        params.append(f"security={config['security']}")
    if config.get('mport'):
        params.append(f"mport={config['mport']}")

    if params:
        url += f"?{'&'.join(params)}"

    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def format_tuic_to_standard(config: Dict) -> str:
    hostname = config['hostname']
    if is_valid_ipv6(hostname):
        url = f"tuic://{config['uuid']}:{config['password']}@[{hostname}]:{config['port']}"
    else:
        url = f"tuic://{config['uuid']}:{config['password']}@{hostname}:{config['port']}"

    params = []
    if config.get('congestion_control', 'bbr') != 'bbr':
        params.append(f"congestion_control={config['congestion_control']}")
    if config.get('udp_relay_mode', 'native') != 'native':
        params.append(f"udp_relay_mode={config['udp_relay_mode']}")
    if config.get('alpn', 'h3') != 'h3':
        params.append(f"alpn={config['alpn']}")
    if config.get('allow_insecure', '0') != '0':
        params.append(f"allow_insecure={config['allow_insecure']}")
    if config.get('sni'):
        params.append(f"sni={config['sni']}")

    if params:
        url += f"?{'&'.join(params)}"

    if config.get('tag'):
        try:
            url += f"#{urllib.parse.quote(str(config['tag']))}"
        except:
            url += f"#{config['tag']}"

    return url


def parse_config(config: str) -> Optional[Dict]:
    config = config.strip()
    # Remove common trailing characters that break parsing
    config = re.sub(r'[⚡️\s]+$', '', config)

    parsers = [
        parse_shadowsocks_config,
        parse_vmess_config,
        parse_vless_config,
        parse_trojan_config,
        parse_ssr_config,
        parse_hysteria_config,
        parse_hysteria2_config,
        parse_tuic_config
    ]

    for parser in parsers:
        try:
            result = parser(config)
            if result and result.get('hostname'):
                if is_valid_hostname(result['hostname']):
                    return result
        except Exception:
            continue

    return None


def format_to_standard(config: Dict) -> str:
    protocol = config.get('protocol', '')

    formatters = {
        'ss': format_shadowsocks_to_standard,
        'vmess': format_vmess_to_standard,
        'vless': format_vless_to_standard,
        'trojan': format_trojan_to_standard,
        'ssr': format_ssr_to_standard,
        'hysteria': format_hysteria_to_standard,
        'hy': format_hysteria_to_standard,
        'hysteria2': format_hysteria2_to_standard,
        'tuic': format_tuic_to_standard
    }

    formatter = formatters.get(protocol)
    if formatter:
        return formatter(config)

    return ""

os.makedirs("reformatted", exist_ok=True)
os.makedirs("broken", exist_ok=True)

def process_protocol_files(protocol: str):
    if protocol == 'hysteria2':
        input_files = [f"config/hy.txt", f"config/hy.decoded.txt", f"config/hysteria2.txt", f"config/hysteria2.decoded.txt"]
    else:
        input_files = [f"config/{protocol}.txt", f"config/{protocol}.decoded.txt"]
    output_file = f"reformatted/{protocol}.txt"
    broken_file = f"broken/{protocol}_configs.txt"

    valid_configs = []
    broken_configs = []
    processed_count = 0

    for file_path in input_files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    valid_prefixes = [f'{protocol}://']
                    if protocol == 'hy':
                        valid_prefixes.extend(['hy://', 'hysteria://'])
                    elif protocol == 'hysteria2':
                        valid_prefixes.extend(['hysteria2://', 'hy2://'])
                    elif protocol == 'ss':
                        valid_prefixes.append('ss://')

                    if not any(line.lower().startswith(prefix) for prefix in valid_prefixes):
                        continue

                    processed_count += 1

                    parsed = parse_config(line)
                    if parsed:
                        expected_protocols = [protocol]
                        if protocol == 'hy':
                            expected_protocols.extend(['hy', 'hysteria'])
                        elif protocol == 'hysteria2':
                            expected_protocols.append('hysteria2')

                        if parsed.get('protocol') in expected_protocols:
                            try:
                                standard_config = format_to_standard(parsed)
                                if standard_config:
                                    valid_configs.append(standard_config)
                                else:
                                    broken_configs.append(line)
                            except Exception:
                                broken_configs.append(line)
                        else:
                            broken_configs.append(line)
                    else:
                        broken_configs.append(line)

        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")

    if processed_count > 0:
        with open(output_file, 'w', encoding='utf-8') as f:
            for config in valid_configs:
                f.write(config + '\n')

        with open(broken_file, 'w', encoding='utf-8') as f:
            for config in broken_configs:
                f.write(config + '\n')

        success_rate = (len(valid_configs) / processed_count * 100) if processed_count > 0 else 0

        print(f"{protocol.upper()} - Processed {processed_count} total configs")
        print(f"{protocol.upper()} - Generated {len(valid_configs)} valid configs -> {output_file}")
        print(f"{protocol.upper()} - Found {len(broken_configs)} broken configs -> {broken_file}")
        print(f"{protocol.upper()} - Success rate: {success_rate:.1f}%")
        print("-" * 50)


        
        
if __name__ == "__main__":
    protocols = ['ss', 'vmess', 'vless', 'trojan', 'ssr', 'hy', 'tuic']

    for protocol in protocols:
        process_protocol_files(protocol)
        
        
        
