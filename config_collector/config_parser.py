import json
import base64
import urllib.parse
import re
import os
from typing import Dict, List, Any, Tuple


class ConfigParser:
    def __init__(self, input_dir: str = "reformatted", output_dir: str = "parsed_configs", failed_dir: str = "failed_configs"):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.failed_dir = failed_dir
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "by_protocol": {}
        }

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(failed_dir, exist_ok=True)

    def parse_ss_config(self, config: str) -> Dict[str, Any]:
        if not config.startswith("ss://"):
            raise ValueError("Invalid SS config format")

        config = config[5:]
        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        query_split = main_part.split("?")
        server_auth = query_split[0]

        at_split = server_auth.split("@")
        if len(at_split) != 2:
            raise ValueError("Invalid SS config structure")

        try:
            b64_data = at_split[0].replace('_', '/').replace('-', '+')

            padding = 4 - len(b64_data) % 4
            if padding != 4:
                padded_data = b64_data + "=" * padding
            else:
                padded_data = b64_data

            auth_data = base64.b64decode(padded_data).decode('utf-8')

            if ":" not in auth_data:
                parts = auth_data.split()
                if len(parts) >= 2:
                    method = parts[0]
                    password = " ".join(parts[1:])
                else:
                    raise ValueError("Invalid auth data format")
            else:
                method, password = auth_data.split(":", 1)
        except Exception as e:
            raise ValueError(f"Failed to decode SS auth data: {str(e)}")

        server_address = at_split[1]

        if server_address.startswith("[") and "]:" in server_address:
            ipv6_end = server_address.find("]:")
            server = server_address[1:ipv6_end]
            port_str = server_address[ipv6_end+2:]
        else:
            server_port = server_address.rsplit(":", 1)
            if len(server_port) != 2:
                raise ValueError("Invalid server:port format")
            server = server_port[0]
            port_str = server_port[1]

        try:
            port = int(port_str)
        except ValueError:
            raise ValueError("Invalid port number")

        result = {
            "server": server,
            "server_port": port,
            "password": password,
            "method": method,
            "name": name
        }

        if len(query_split) > 1:
            params = urllib.parse.parse_qs(query_split[1])
            for key, value in params.items():
                result[key] = value[0] if len(value) == 1 else value

        return result

    def parse_vless_config(self, config: str) -> Dict[str, Any]:
        if not config.startswith("vless://"):
            raise ValueError("Invalid VLESS config format")

        config = config[8:]
        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        at_pos = main_part.find("@")
        if at_pos == -1:
            raise ValueError("Invalid VLESS config structure")

        uuid = main_part[:at_pos]
        server_part = main_part[at_pos+1:]
        if not uuid:
            raise ValueError("Missing UUID")

        server_params = server_part.split("?")

        if len(server_params) < 1:
            raise ValueError("Invalid VLESS server params")

        server_address = server_params[0]

        if server_address.startswith("[") and "]:" in server_address:
            ipv6_end = server_address.find("]:")
            address = server_address[1:ipv6_end]
            port_str = server_address[ipv6_end+2:]
        else:
            server_port = server_address.rsplit(":", 1)
            if len(server_port) != 2:
                raise ValueError("Invalid server:port format")
            address = server_port[0]
            port_str = server_port[1]

        try:
            port = int(port_str)
        except ValueError:
            raise ValueError("Invalid port number")

        result = {
            "address": address,
            "port": port,
            "id": uuid,
            "name": name
        }

        if len(server_params) > 1:
            try:
                params = urllib.parse.parse_qs(server_params[1], keep_blank_values=True)
                for key, value in params.items():
                    if key == "authority":
                        result["serviceName"] = value[0] if len(value) == 1 else value
                    elif key == "serviceName":
                        result["serviceName"] = value[0] if len(value) == 1 else value
                    else:
                        result[key] = value[0] if len(value) == 1 else value
            except Exception as e:
                raw_params = server_params[1].split('&')
                for param in raw_params:
                    if '=' in param:
                        k, v = param.split('=', 1)
                        if k == "authority":
                            result["serviceName"] = urllib.parse.unquote(v)
                        elif k == "serviceName":
                            result["serviceName"] = urllib.parse.unquote(v)
                        else:
                            result[k] = urllib.parse.unquote(v)

        return result

    def parse_vmess_config(self, config: str) -> Dict[str, Any]:
        if not config.startswith("vmess://"):
            raise ValueError("Invalid VMess config format")

        config = config[8:]
        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        try:
            b64_data = parts[0]

            padding = 4 - len(b64_data) % 4
            if padding != 4:
                padded_data = b64_data + "=" * padding
            else:
                padded_data = b64_data

            try:
                json_data = base64.b64decode(padded_data).decode('utf-8')
            except:
                try:
                    import binascii
                    json_data = base64.b64decode(padded_data, validate=False).decode('utf-8', errors='ignore')
                except:
                    json_data = base64.b64decode(padded_data + "=", validate=False).decode('utf-8', errors='ignore')

            json_data = re.sub(r'[\x00-\x1F\x7F]', '', json_data)
            json_data = json_data.replace('\\u', 'u')
            json_data = re.sub(r'\\[^"nrtbf/\\]', '', json_data)
            vmess_config = json.loads(json_data)
        except Exception as e:
            raise ValueError(f"Failed to decode VMess JSON data: {str(e)}")

        if not isinstance(vmess_config, dict):
            raise ValueError("Invalid VMess JSON structure")

        address = vmess_config.get("add", "")
        if not address:
            raise ValueError("Missing address in VMess config")

        try:
            port = int(vmess_config.get("port", 0))
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
        except (ValueError, TypeError):
            raise ValueError("Invalid port number")

        uuid = vmess_config.get("id", "")
        if not uuid:
            raise ValueError("Missing UUID")

        network = vmess_config.get("net", "tcp")
        if not network:
            network = "tcp"

        result = {
            "address": address,
            "port": port,
            "id": uuid,
            "security": vmess_config.get("scy", "auto"),
            "network": network,
            "name": name
        }

        for key, value in vmess_config.items():
            if key not in ["add", "port", "id", "scy", "net"] and value and value != "---":
                if key == "type" and value == "---":
                    continue
                result[key] = value

        return result

    def parse_trojan_config(self, config: str) -> Dict[str, Any]:
        if not config.startswith("trojan://"):
            raise ValueError("Invalid Trojan config format")

        config = config[9:]
        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        at_pos = main_part.find("@")
        if at_pos == -1:
            raise ValueError("Invalid Trojan config structure")

        password = main_part[:at_pos]
        server_part = main_part[at_pos+1:]
        if not password:
            raise ValueError("Missing password")

        server_params = server_part.split("?")
        server_address = server_params[0]

        if server_address.startswith("[") and "]:" in server_address:
            ipv6_end = server_address.find("]:")
            address = server_address[1:ipv6_end]
            port_str = server_address[ipv6_end+2:]
        else:
            server_port = server_address.rsplit(":", 1)
            if len(server_port) != 2:
                raise ValueError("Invalid server:port format")
            address = server_port[0]
            port_str = server_port[1]

        try:
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
        except ValueError:
            raise ValueError("Invalid port number")

        result = {
            "address": address,
            "port": port,
            "password": password,
            "name": name
        }

        if len(server_params) > 1:
            try:
                param_string = server_params[1]
                param_string = re.sub(r'security=none=', '', param_string)
                param_string = re.sub(r'serviceName=/[🔒🆔][^&]*', '', param_string)
                param_string = re.sub(r'sni=[🔒🆔][^&]*', '', param_string)

                params = urllib.parse.parse_qs(param_string, keep_blank_values=True)
                for key, value in params.items():
                    if key == "security" and value[0] == "none":
                        continue
                    if key == "sni":
                        if not value[0] or "🔒" in str(value[0]) or "🆔" in str(value[0]):
                            continue
                    result[key] = value[0] if len(value) == 1 else value
            except Exception:
                raw_params = server_params[1].split('&')
                for param in raw_params:
                    if '=' in param and not param.startswith('security=none='):
                        k, v = param.split('=', 1)
                        if k == "sni" and ("🔒" in v or "🆔" in v):
                            continue
                        result[k] = urllib.parse.unquote(v)

        return result

    def parse_ssr_config(self, config: str) -> Dict[str, Any]:
        """Parse ShadowsocksR configuration."""
        if not config.startswith("ssr://"):
            raise ValueError("Invalid SSR config format")

        config = config[6:]
        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        # Decode base64
        try:
            padding = 4 - len(main_part) % 4
            if padding != 4:
                padded_data = main_part + "=" * padding
            else:
                padded_data = main_part

            decoded = base64.b64decode(padded_data).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Failed to decode SSR config: {str(e)}")

        # Split by /
        split_parts = decoded.split('/')
        if len(split_parts) < 1:
            raise ValueError("Invalid SSR structure")

        main_data = split_parts[0]
        query_part = split_parts[1] if len(split_parts) > 1 else ''

        # Parse main part: server:port:protocol:method:obfs:password_base64
        components = main_data.split(':')
        if len(components) != 6:
            raise ValueError("Invalid SSR main part structure")

        server, port_str, protocol, method, obfs, password_b64 = components

        try:
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
        except ValueError:
            raise ValueError("Invalid port number")

        # Decode password
        try:
            padding = 4 - len(password_b64) % 4
            if padding != 4:
                padded_pw = password_b64 + "=" * padding
            else:
                padded_pw = password_b64
            password = base64.b64decode(padded_pw).decode('utf-8')
        except:
            password = password_b64

        result = {
            "server": server,
            "server_port": port,
            "protocol": protocol,
            "method": method,
            "obfs": obfs,
            "password": password,
            "name": name
        }

        # Parse query parameters
        if query_part.startswith('?'):
            query_part = query_part[1:]

        for param in query_part.split('&'):
            if '=' in param:
                key, value = param.split('=', 1)
                try:
                    padding = 4 - len(value) % 4
                    if padding != 4:
                        padded_val = value + "=" * padding
                    else:
                        padded_val = value
                    decoded_value = base64.b64decode(padded_val).decode('utf-8')
                    result[key] = decoded_value
                except:
                    result[key] = value

        return result

    def parse_hysteria_config(self, config: str) -> Dict[str, Any]:
        """Parse Hysteria/Hysteria1 configuration."""
        if not config.startswith("hysteria://") and not config.startswith("hy://"):
            raise ValueError("Invalid Hysteria config format")

        if config.startswith("hysteria://"):
            config = config[11:]
        else:
            config = config[5:]

        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        server_params = main_part.split("?")
        server_address = server_params[0]

        # Parse server:port
        if server_address.startswith("[") and "]:" in server_address:
            ipv6_end = server_address.find("]:")
            address = server_address[1:ipv6_end]
            port_str = server_address[ipv6_end+2:]
        else:
            server_port = server_address.rsplit(":", 1)
            if len(server_port) != 2:
                raise ValueError("Invalid server:port format")
            address = server_port[0]
            port_str = server_port[1]

        try:
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
        except ValueError:
            raise ValueError("Invalid port number")

        result = {
            "address": address,
            "port": port,
            "name": name
        }

        # Parse parameters
        if len(server_params) > 1:
            params = urllib.parse.parse_qs(server_params[1])
            for key, value in params.items():
                result[key] = value[0] if len(value) == 1 else value

        return result

    def parse_hysteria2_config(self, config: str) -> Dict[str, Any]:
        """Parse Hysteria2 configuration."""
        if not config.startswith("hysteria2://") and not config.startswith("hy2://"):
            raise ValueError("Invalid Hysteria2 config format")

        if config.startswith("hysteria2://"):
            config = config[12:]
        else:
            config = config[6:]

        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        # Parse auth@server:port
        if "@" not in main_part:
            raise ValueError("Invalid Hysteria2 config structure")

        auth_part, server_part = main_part.split("@", 1)

        # Remove trailing /
        if "/" in server_part:
            server_addr, path_query = server_part.split("/", 1)
        else:
            server_addr = server_part
            path_query = ""

        # Parse query parameters
        if "?" in path_query:
            path, query_part = path_query.split("?", 1)
        else:
            query_part = ""

        # Parse server:port
        if server_addr.startswith("[") and "]:" in server_addr:
            ipv6_end = server_addr.find("]:")
            address = server_addr[1:ipv6_end]
            port_str = server_addr[ipv6_end+2:]
        else:
            server_port = server_addr.rsplit(":", 1)
            if len(server_port) != 2:
                raise ValueError("Invalid server:port format")
            address = server_port[0]
            port_str = server_port[1]

        try:
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
        except ValueError:
            raise ValueError("Invalid port number")

        result = {
            "address": address,
            "port": port,
            "auth": auth_part,
            "name": name
        }

        # Parse parameters
        if query_part:
            params = urllib.parse.parse_qs(query_part)
            for key, value in params.items():
                result[key] = value[0] if len(value) == 1 else value

        return result

    def parse_tuic_config(self, config: str) -> Dict[str, Any]:
        """Parse TUIC configuration."""
        if not config.startswith("tuic://"):
            raise ValueError("Invalid TUIC config format")

        config = config[7:]
        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        # Parse uuid:password@server:port
        if "@" not in main_part:
            raise ValueError("Invalid TUIC config structure")

        userinfo_part, server_part = main_part.split("@", 1)

        if ":" not in userinfo_part:
            raise ValueError("Invalid TUIC userinfo")

        uuid, password = userinfo_part.split(":", 1)

        # Parse server and query params
        server_params = server_part.split("?")
        server_address = server_params[0]

        # Parse server:port
        if server_address.startswith("[") and "]:" in server_address:
            ipv6_end = server_address.find("]:")
            address = server_address[1:ipv6_end]
            port_str = server_address[ipv6_end+2:]
        else:
            server_port = server_address.rsplit(":", 1)
            if len(server_port) != 2:
                raise ValueError("Invalid server:port format")
            address = server_port[0]
            port_str = server_port[1]

        try:
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
        except ValueError:
            raise ValueError("Invalid port number")

        result = {
            "address": address,
            "port": port,
            "uuid": uuid,
            "password": password,
            "name": name
        }

        # Parse parameters
        if len(server_params) > 1:
            params = urllib.parse.parse_qs(server_params[1])
            for key, value in params.items():
                result[key] = value[0] if len(value) == 1 else value

        return result

    def parse_wireguard_config(self, config: str) -> Dict[str, Any]:
        """Parse WireGuard configuration."""
        if not config.startswith("wireguard://"):
            raise ValueError("Invalid WireGuard config format")

        config = config[12:]
        parts = config.split("#")
        name = urllib.parse.unquote(parts[1]) if len(parts) > 1 else ""

        main_part = parts[0]

        # WireGuard format can vary, implementing basic parsing
        # Format: wireguard://private_key@server:port?params

        if "@" in main_part:
            key_part, server_part = main_part.split("@", 1)
        else:
            raise ValueError("Invalid WireGuard config structure")

        # Parse server and query params
        server_params = server_part.split("?")
        server_address = server_params[0]

        # Parse server:port
        if server_address.startswith("[") and "]:" in server_address:
            ipv6_end = server_address.find("]:")
            address = server_address[1:ipv6_end]
            port_str = server_address[ipv6_end+2:]
        else:
            server_port = server_address.rsplit(":", 1)
            if len(server_port) != 2:
                raise ValueError("Invalid server:port format")
            address = server_port[0]
            port_str = server_port[1]

        try:
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError("Invalid port number")
        except ValueError:
            raise ValueError("Invalid port number")

        result = {
            "address": address,
            "port": port,
            "private_key": key_part,
            "name": name
        }

        # Parse parameters
        if len(server_params) > 1:
            params = urllib.parse.parse_qs(server_params[1])
            for key, value in params.items():
                result[key] = value[0] if len(value) == 1 else value

        return result

    def parse_config_line(self, line: str, protocol: str) -> Dict[str, Any]:
        line = line.strip()
        if not line:
            raise ValueError("Empty config line")

        if protocol == "ss":
            return self.parse_ss_config(line)
        elif protocol == "vless":
            return self.parse_vless_config(line)
        elif protocol == "vmess":
            return self.parse_vmess_config(line)
        elif protocol == "trojan":
            return self.parse_trojan_config(line)
        elif protocol == "ssr":
            return self.parse_ssr_config(line)
        elif protocol == "hy" or protocol == "hysteria":
            return self.parse_hysteria_config(line)
        elif protocol == "hysteria2":
            return self.parse_hysteria2_config(line)
        elif protocol == "tuic":
            return self.parse_tuic_config(line)
        elif protocol == "wireguard":
            return self.parse_wireguard_config(line)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def process_file(self, filename: str) -> Tuple[List[Dict], List[str]]:
        protocol = filename.replace(".txt", "")
        filepath = os.path.join(self.input_dir, filename)

        successful_configs = []
        failed_configs = []

        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue

                self.stats["total"] += 1

                try:
                    parsed_config = self.parse_config_line(line, protocol)
                    successful_configs.append(parsed_config)
                    self.stats["success"] += 1
                except Exception as e:
                    failed_configs.append(f"Line {line_num}: {line}")
                    self.stats["failed"] += 1

        return successful_configs, failed_configs

    def save_configs(self, protocol: str, configs: List[Dict], failed: List[str]):
        if configs:
            output_file = os.path.join(self.output_dir, f"{protocol}.json")
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(configs, f, indent=2, ensure_ascii=False)

        if failed:
            failed_file = os.path.join(self.failed_dir, f"{protocol}_failed.txt")
            with open(failed_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(failed))

        self.stats["by_protocol"][protocol] = {
            "success": len(configs),
            "failed": len(failed)
        }

    def process_all_files(self):

        files = ["ss.txt", "vless.txt", "vmess.txt", "trojan.txt", "ssr.txt", "hy.txt", "hysteria2.txt", "tuic.txt", "wireguard.txt"]

        for filename in files:
            filepath = os.path.join(self.input_dir, filename)
            if os.path.exists(filepath):
                protocol = filename.replace(".txt", "")
                print(f"Processing {protocol} configs...")

                successful_configs, failed_configs = self.process_file(filename)
                self.save_configs(protocol, successful_configs, failed_configs)

        self.print_statistics()

    def print_statistics(self):
        print("\n=== Config Processing Statistics ===")
        print(f"Total configs processed: {self.stats['total']}")
        print(f"Successfully parsed: {self.stats['success']}")
        print(f"Failed to parse: {self.stats['failed']}")
        print(f"Success rate: {(self.stats['success']/self.stats['total']*100):.2f}%" if self.stats['total'] > 0 else "N/A")

        print("\n=== By Protocol ===")
        for protocol, stats in self.stats["by_protocol"].items():
            total_protocol = stats["success"] + stats["failed"]
            success_rate = (stats["success"]/total_protocol*100) if total_protocol > 0 else 0
            print(f"{protocol.upper()}: {stats['success']}/{total_protocol} ({success_rate:.2f}%)")

parser = ConfigParser()

if __name__ == "__main__":
    parser.process_all_files()
