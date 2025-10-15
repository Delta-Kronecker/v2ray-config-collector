import json
import os
import base64
import urllib.parse
import random
from typing import Dict, List, Any, Tuple
from collections import defaultdict


class ConfigDeduplicator:
    def __init__(self, input_dir: str = "parsed_configs", output_dir: str = "../data/deduplicated_urls"):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.stats = {
            "input_total": 0,
            "processed_total": 0,
            "failed_total": 0,
            "by_protocol": {}
        }

        os.makedirs(output_dir, exist_ok=True)

    def count_non_empty_params(self, config: Dict[str, Any]) -> int:
        count = 0
        for key, value in config.items():
            if value and str(value).strip() and str(value) not in ["", "0", "false", "None", "null"]:
                count += 1
        return count

    def get_address_port(self, config: Dict[str, Any]) -> Tuple[str, int]:
        if "server" in config and "server_port" in config:
            return config["server"], config["server_port"]
        elif "address" in config and "port" in config:
            return config["address"], config["port"]
        else:
            raise ValueError("Missing address/port information")

    def deduplicate_configs(self, configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        groups = defaultdict(list)

        for config in configs:
            try:
                address, port = self.get_address_port(config)
                key = (address, port)
                groups[key].append(config)
            except:
                continue

        deduplicated = []
        for group in groups.values():
            if len(group) == 1:
                selected_config = group[0].copy()
            else:
                selected_config = max(group, key=self.count_non_empty_params).copy()

            selected_config["name"] = "🔥"
            deduplicated.append(selected_config)

        return deduplicated

    def ss_to_url(self, config: Dict[str, Any]) -> str:
        method = config.get("method", "")
        password = config.get("password", "")
        server = config.get("server", "")
        port = config.get("server_port", 0)
        name = config.get("name", "")

        if not all([method, password, server, port]):
            raise ValueError("Missing required SS parameters")

        auth_string = f"{method}:{password}"
        b64_auth = base64.b64encode(auth_string.encode()).decode().rstrip('=')

        url = f"ss://{b64_auth}@{server}:{port}"

        params = {}
        for key, value in config.items():
            if key not in ["method", "password", "server", "server_port", "name"] and value:
                params[key] = str(value)

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def vless_to_url(self, config: Dict[str, Any]) -> str:
        uuid = config.get("id", "")
        address = config.get("address", "")
        port = config.get("port", 0)
        name = config.get("name", "")

        if not all([uuid, address, port]):
            raise ValueError("Missing required VLESS parameters")

        url = f"vless://{uuid}@{address}:{port}"

        params = {}
        for key, value in config.items():
            if key not in ["id", "address", "port", "name"] and value:
                if key == "serviceName":
                    params["serviceName"] = str(value)
                else:
                    params[key] = str(value)

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def vmess_to_url(self, config: Dict[str, Any]) -> str:
        vmess_config = {}

        address = config.get("address", "")
        port = config.get("port", 0)
        uuid = config.get("id", "")

        if not all([address, port, uuid]):
            raise ValueError("Missing required VMess parameters")

        vmess_config["add"] = address
        vmess_config["port"] = str(port)
        vmess_config["id"] = uuid
        vmess_config["net"] = config.get("network", "tcp")
        vmess_config["scy"] = config.get("security", "auto")

        for key, value in config.items():
            if key not in ["address", "port", "id", "network", "security", "name"] and value:
                if key == "v":
                    vmess_config["v"] = str(value)
                elif key == "aid":
                    vmess_config["aid"] = str(value)
                elif key == "type":
                    vmess_config["type"] = str(value)
                elif key == "host":
                    vmess_config["host"] = str(value)
                elif key == "path":
                    vmess_config["path"] = str(value)
                elif key == "tls":
                    vmess_config["tls"] = str(value)
                elif key == "sni":
                    vmess_config["sni"] = str(value)
                else:
                    vmess_config[key] = str(value)

        json_str = json.dumps(vmess_config, separators=(',', ':'))
        b64_config = base64.b64encode(json_str.encode()).decode()

        url = f"vmess://{b64_config}"

        name = config.get("name", "")
        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def trojan_to_url(self, config: Dict[str, Any]) -> str:
        password = config.get("password", "")
        address = config.get("address", "")
        port = config.get("port", 0)
        name = config.get("name", "")

        if not all([password, address, port]):
            raise ValueError("Missing required Trojan parameters")

        url = f"trojan://{password}@{address}:{port}"

        params = {}
        for key, value in config.items():
            if key not in ["password", "address", "port", "name"] and value:
                params[key] = str(value)

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def ssr_to_url(self, config: Dict[str, Any]) -> str:
        server = config.get("server", "")
        port = config.get("server_port", 0)
        protocol = config.get("protocol", "")
        method = config.get("method", "")
        obfs = config.get("obfs", "")
        password = config.get("password", "")
        name = config.get("name", "")

        if not all([server, port, protocol, method, obfs, password]):
            raise ValueError("Missing required SSR parameters")

        # Encode password
        password_b64 = base64.b64encode(password.encode()).decode().rstrip('=')

        # Main part: server:port:protocol:method:obfs:password_base64
        main_part = f"{server}:{port}:{protocol}:{method}:{obfs}:{password_b64}"

        # Add query parameters
        params = []
        for key, value in config.items():
            if key not in ["server", "server_port", "protocol", "method", "obfs", "password", "name"] and value:
                encoded_value = base64.b64encode(str(value).encode()).decode().rstrip('=')
                params.append(f"{key}={encoded_value}")

        if params:
            main_part += "/?" + "&".join(params)

        # Encode the whole thing
        encoded = base64.b64encode(main_part.encode()).decode().rstrip('=')
        url = f"ssr://{encoded}"

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def hysteria_to_url(self, config: Dict[str, Any]) -> str:
        address = config.get("address", "")
        port = config.get("port", 0)
        name = config.get("name", "")

        if not all([address, port]):
            raise ValueError("Missing required Hysteria parameters")

        url = f"hy://{address}:{port}"

        params = {}
        for key, value in config.items():
            if key not in ["address", "port", "name"] and value:
                params[key] = str(value)

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def hysteria2_to_url(self, config: Dict[str, Any]) -> str:
        address = config.get("address", "")
        port = config.get("port", 0)
        auth = config.get("auth", "")
        name = config.get("name", "")

        if not all([address, port, auth]):
            raise ValueError("Missing required Hysteria2 parameters")

        url = f"hysteria2://{auth}@{address}:{port}/"

        params = {}
        for key, value in config.items():
            if key not in ["address", "port", "auth", "name"] and value:
                params[key] = str(value)

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def tuic_to_url(self, config: Dict[str, Any]) -> str:
        address = config.get("address", "")
        port = config.get("port", 0)
        uuid = config.get("uuid", "")
        password = config.get("password", "")
        name = config.get("name", "")

        if not all([address, port, uuid, password]):
            raise ValueError("Missing required TUIC parameters")

        url = f"tuic://{uuid}:{password}@{address}:{port}"

        params = {}
        for key, value in config.items():
            if key not in ["address", "port", "uuid", "password", "name"] and value:
                params[key] = str(value)

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def wireguard_to_url(self, config: Dict[str, Any]) -> str:
        address = config.get("address", "")
        port = config.get("port", 0)
        private_key = config.get("private_key", "")
        name = config.get("name", "")

        if not all([address, port, private_key]):
            raise ValueError("Missing required WireGuard parameters")

        url = f"wireguard://{private_key}@{address}:{port}"

        params = {}
        for key, value in config.items():
            if key not in ["address", "port", "private_key", "name"] and value:
                params[key] = str(value)

        if params:
            url += "?" + urllib.parse.urlencode(params)

        if name:
            url += "#" + urllib.parse.quote(name)

        return url

    def config_to_url(self, config: Dict[str, Any], protocol: str) -> str:
        if protocol == "ss":
            return self.ss_to_url(config)
        elif protocol == "vless":
            return self.vless_to_url(config)
        elif protocol == "vmess":
            return self.vmess_to_url(config)
        elif protocol == "trojan":
            return self.trojan_to_url(config)
        elif protocol == "ssr":
            return self.ssr_to_url(config)
        elif protocol == "hy" or protocol == "hysteria":
            return self.hysteria_to_url(config)
        elif protocol == "hysteria2":
            return self.hysteria2_to_url(config)
        elif protocol == "tuic":
            return self.tuic_to_url(config)
        elif protocol == "wireguard":
            return self.wireguard_to_url(config)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

    def process_protocol(self, protocol: str):
        input_file = os.path.join(self.input_dir, f"{protocol}.json")

        if not os.path.exists(input_file):
            return

        with open(input_file, 'r', encoding='utf-8') as f:
            configs = json.load(f)

        input_count = len(configs)
        self.stats["input_total"] += input_count

        deduplicated_configs = self.deduplicate_configs(configs)

        # Randomize the order of configs
        random.shuffle(deduplicated_configs)

        urls = []
        failed_count = 0

        for config in deduplicated_configs:
            try:
                url = self.config_to_url(config, protocol)
                urls.append(url)
            except Exception:
                failed_count += 1

        processed_count = len(urls)
        self.stats["processed_total"] += processed_count
        self.stats["failed_total"] += failed_count

        self.stats["by_protocol"][protocol] = {
            "input": input_count,
            "processed": processed_count,
            "failed": failed_count
        }

        # Randomize the order of URLs
        random.shuffle(urls)

        if urls:
            # Save URLs as text file
            output_file = os.path.join(self.output_dir, f"{protocol}_urls.txt")
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(urls))

            # Save unique configs as JSON file with same structure as parsed_configs
            json_output_file = os.path.join(self.output_dir, f"{protocol}.json")
            with open(json_output_file, 'w', encoding='utf-8') as f:
                json.dump(deduplicated_configs, f, ensure_ascii=False, indent=2)

    def process_all_protocols(self):
        protocols = ["ss", "vless", "vmess", "trojan", "ssr", "hy", "hysteria2", "tuic", "wireguard"]

        for protocol in protocols:
            self.process_protocol(protocol)

        self.print_statistics()

    def print_statistics(self):
        print("=== Configuration Processing Statistics ===")
        print(f"Total input configs: {self.stats['input_total']}")
        print(f"Unique configs extracted: {self.stats['processed_total']}")
        print(f"Failed configs: {self.stats['failed_total']}")

        total_conversion_attempts = self.stats['processed_total'] + self.stats['failed_total']
        if total_conversion_attempts > 0:
            success_rate = (self.stats['processed_total'] / total_conversion_attempts) * 100
            print(f"Success rate: {success_rate:.2f}%")

        print("\n=== Statistics by Protocol ===")
        for protocol, stats in self.stats["by_protocol"].items():
            print(f"{protocol.upper()}: Input={stats['input']}, Unique={stats['processed']}, Failed={stats['failed']}")


if __name__ == "__main__":
    deduplicator = ConfigDeduplicator()
    deduplicator.process_all_protocols()
