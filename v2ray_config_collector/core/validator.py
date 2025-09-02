import socket
import os
import time
import threading
import queue
from datetime import datetime
import sys
import base64
import binascii
import json

class ConnectivityValidator:
    def __init__(self, input_file=None, output_dir=None):
        # استفاده از مسیرهای نسبی نسبت به محل اجرای اسکریپت
        current_dir = os.path.dirname(os.path.abspath(__file__))
        print(f"Current directory: {current_dir}")

        if input_file is None:
            input_file = os.path.join(current_dir, 'data', 'unique', 'deduplicated.txt')
        if output_dir is None:
            output_dir = os.path.join(current_dir, 'data', 'validated')

        self.input_file = input_file
        self.output_dir = output_dir
        self.valid_configs_dir = os.path.join(self.output_dir, 'working_configs')
        
        print(f"Input file: {self.input_file}")
        print(f"Output directory: {self.output_dir}")
        print(f"Valid configs directory: {self.valid_configs_dir}")
        
        # ایجاد دایرکتوری‌ها
        os.makedirs(self.valid_configs_dir, exist_ok=True)
        print(f"Created directory: {self.valid_configs_dir}")

        self.stats = {
            'total_configs': 0,
            'tested_configs': 0,
            'valid_configs': 0,
            'invalid_configs': 0,
            'by_protocol': {},
            'timeout_configs': 0,
            'connection_error_configs': 0,
            'parse_error_configs': 0
        }
        self.valid_configs = {}
        self.max_workers = 100
        self.timeout = 5
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.progress_interval = 10

    def read_configs(self):
        try:
            print(f"Attempting to read file: {self.input_file}")
            if not os.path.exists(self.input_file):
                print(f"Input file does not exist: {self.input_file}")
                return []
                
            with open(self.input_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            configs = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
            self.stats['total_configs'] = len(configs)
            print(f"Read {len(configs)} configurations from {self.input_file}")
            return configs
        except Exception as e:
            print(f"Error reading configurations: {e}")
            return []

    def detect_protocol(self, config_url):
        if config_url.startswith('vmess://'):
            return 'vmess'
        elif config_url.startswith('vless://'):
            return 'vless'
        elif config_url.startswith('trojan://'):
            return 'trojan'
        elif config_url.startswith('ss://'):
            return 'shadowsocks'
        elif config_url.startswith('ssr://'):
            return 'ssr'
        elif config_url.startswith('tuic://'):
            return 'tuic'
        elif config_url.startswith(('hysteria2://', 'hy2://')):
            return 'hysteria2'
        else:
            return 'unknown'

    def extract_server_port(self, config_url):
        try:
            protocol = self.detect_protocol(config_url)
            if protocol == 'unknown':
                return None, None

            url_data = config_url.replace(f"{protocol}://", "")

            if protocol == 'vmess':
                try:
                    decoded_data = base64.b64decode(url_data).decode('utf-8')
                    vmess_config = json.loads(decoded_data)
                    server = vmess_config.get('add')
                    port = vmess_config.get('port')
                    if server and port:
                        try:
                            port = int(port)
                            return server, port
                        except ValueError:
                            return None, None
                    return None, None
                except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
                    return None, None

            if '@' in url_data:
                server_part = url_data.split('@', 1)[1]
                if '?' in server_part:
                    server_part = server_part.split('?', 1)[0]
                if '#' in server_part:
                    server_part = server_part.split('#', 1)[0]
                if ':' in server_part:
                    server, port_str = server_part.split(':', 1)
                    if '/' in port_str:
                        port_str = port_str.split('/', 1)[0]
                    try:
                        port = int(port_str)
                    except ValueError:
                        port = 443
                else:
                    server = server_part
                    port = 443
                return server, port

            return None, None
        except Exception as e:
            print(f"Error extracting server/port from {config_url[:30]}...: {str(e)}")
            return None, None

    def test_tcp_connection(self, server, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect((server, port))
            sock.close()
            return True
        except socket.timeout:
            return False, "timeout"
        except ConnectionRefusedError:
            return False, "connection_refused"
        except socket.gaierror:
            return False, "dns_resolution_failed"
        except Exception as e:
            return False, str(e)
        finally:
            sock.close()

    def test_config(self, config_url):
        protocol = self.detect_protocol(config_url)
        with self.lock:
            if protocol not in self.stats['by_protocol']:
                self.stats['by_protocol'][protocol] = {
                    'total': 0,
                    'valid': 0,
                    'invalid': 0
                }
            self.stats['by_protocol'][protocol]['total'] += 1

        server, port = self.extract_server_port(config_url)
        if not server or not port:
            with self.lock:
                self.stats['tested_configs'] += 1
                self.stats['invalid_configs'] += 1
                self.stats['parse_error_configs'] += 1
                self.stats['by_protocol'][protocol]['invalid'] += 1
            return

        try:
            result = self.test_tcp_connection(server, port)
            with self.lock:
                self.stats['tested_configs'] += 1
                if isinstance(result, tuple):
                    is_valid, reason = result
                    self.stats['invalid_configs'] += 1
                    self.stats['by_protocol'][protocol]['invalid'] += 1
                    if reason == "timeout":
                        self.stats['timeout_configs'] += 1
                    else:
                        self.stats['connection_error_configs'] += 1
                else:
                    is_valid = result
                    if is_valid:
                        self.stats['valid_configs'] += 1
                        self.stats['by_protocol'][protocol]['valid'] += 1
                        if protocol not in self.valid_configs:
                            self.valid_configs[protocol] = []
                        self.valid_configs[protocol].append(config_url)
                    else:
                        self.stats['invalid_configs'] += 1
                        self.stats['by_protocol'][protocol]['invalid'] += 1
        except Exception as e:
            with self.lock:
                self.stats['tested_configs'] += 1
                self.stats['invalid_configs'] += 1
                self.stats['connection_error_configs'] += 1
                self.stats['by_protocol'][protocol]['invalid'] += 1

    def worker(self):
        while True:
            try:
                config_url = self.queue.get(block=False)
                self.test_config(config_url)
                self.queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                print(f"Worker error: {e}")
                self.queue.task_done()

    def display_progress(self):
        tested = self.stats['tested_configs']
        total = self.stats['total_configs']
        if total == 0:
            progress = 0
        else:
            progress = (tested / total) * 100
        valid = self.stats['valid_configs']
        invalid = self.stats['invalid_configs']
        valid_percentage = (valid / tested) * 100 if tested > 0 else 0
        print(f"\rProgress: {tested}/{total} configs ({progress:.1f}%) | Valid: {valid} ({valid_percentage:.1f}%) | Invalid: {invalid}", end="")
        sys.stdout.flush()

    def test_all_configs(self):
        configs = self.read_configs()
        if not configs:
            print("No configurations found to test!")
            return

        for config in configs:
            self.queue.put(config)

        print(f"Starting TCP testing with {self.max_workers} workers...")
        print(f"Connection timeout set to {self.timeout} seconds")

        threads = []
        for _ in range(min(self.max_workers, self.queue.qsize())):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)

        start_time = time.time()
        last_progress_time = start_time

        try:
            while not self.queue.empty():
                current_time = time.time()
                if current_time - last_progress_time > self.progress_interval:
                    self.display_progress()
                    last_progress_time = current_time
                time.sleep(0.5)

            self.queue.join()
            self.display_progress()
            print("\nTesting completed!")
        except KeyboardInterrupt:
            print("\nTesting interrupted by user!")

        duration = time.time() - start_time
        minutes, seconds = divmod(duration, 60)
        self.display_summary(duration)
        self.save_valid_configs()

    def display_summary(self, duration):
        minutes, seconds = divmod(duration, 60)
        hours, minutes = divmod(minutes, 60)
        configs_per_second = self.stats['tested_configs'] / duration if duration > 0 else 0

        success_rate = (self.stats['valid_configs'] / self.stats['tested_configs'] * 100) if self.stats['tested_configs'] > 0 else 0

        title = "TCP Connection Test Results - Final Summary"
        print(f"\n{title}")
        print("=" * len(title))

        subtitle = "Time and Performance Information:"
        print(subtitle)
        print("-" * len(subtitle))
        if hours > 0:
            print(f"   Test duration: {int(hours)}h {int(minutes)}m {int(seconds)}s")
        else:
            print(f"   Test duration: {int(minutes)}m {int(seconds)}s")
        print(f"   Test speed: {configs_per_second:.2f} configs per second")
        print(f"   Completion date/time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        subtitle = "Overall Statistics:"
        print(f"\n{subtitle}")
        print("-" * len(subtitle))
        print(f"   Tested configurations: {self.stats['tested_configs']:,}")
        print(f"   Valid configurations: {self.stats['valid_configs']:,} ({success_rate:.2f}%)")
        print(f"   Invalid configurations: {self.stats['invalid_configs']:,} ({(self.stats['invalid_configs'] / self.stats['tested_configs'] * 100):.2f}%)")

        if self.stats['valid_configs'] > 0:
            print(f"\n✅ Found {self.stats['valid_configs']} valid configurations!")
        else:
            print("\n❌ No valid configurations found!")

        subtitle = "Protocol Analysis:"
        print(f"\n{subtitle}")
        print("-" * len(subtitle))

        sorted_protocols = sorted(self.stats['by_protocol'].items(), 
                                 key=lambda x: (x[1]['valid'] / x[1]['total'] if x[1]['total'] > 0 else 0, x[1]['total']), 
                                 reverse=True)

        print(f"{'Protocol':<15} {'Total':<10} {'Valid':<10} {'Invalid':<10} {'Success Rate':<15}")
        print("-" * 70)

        for protocol, stats in sorted_protocols:
            if stats['total'] > 0:
                valid_percentage = (stats['valid'] / stats['total']) * 100
                print(f"  {protocol:<13} {stats['total']:<10} {stats['valid']:<10} {stats['invalid']:<10} {valid_percentage:<14.2f}%")

    def save_valid_configs(self):
        print(f"\n{'='*50}")
        print("SAVING VALID CONFIGURATIONS")
        print(f"{'='*50}")
        
        print(f"Output directory: {self.valid_configs_dir}")
        print(f"Directory exists: {os.path.exists(self.valid_configs_dir)}")
        
        # اطمینان از وجود دایرکتوری
        os.makedirs(self.valid_configs_dir, exist_ok=True)

        total_saved = 0
        
        # ذخیره فایل‌های جداگانه برای هر پروتکل
        for protocol, configs in self.valid_configs.items():
            if not configs:
                continue

            protocol_file = os.path.join(self.valid_configs_dir, f"{protocol}_valid.txt")
            try:
                with open(protocol_file, 'w', encoding='utf-8') as f:
                    f.write(f"# Valid {protocol.upper()} Configurations - TCP Test Passed\n")
                    f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"# Total valid configs: {len(configs)}\n\n")
                    for config in configs:
                        f.write(f"{config}\n")
                
                file_size = os.path.getsize(protocol_file)
                print(f"✅ Saved {len(configs)} valid {protocol} configurations to {protocol_file}")
                print(f"   File size: {file_size} bytes")
                total_saved += len(configs)
            except Exception as e:
                print(f"❌ Error saving {protocol} configurations: {e}")

        # ذخیره فایل ترکیبی
        try:
            all_valid_file = os.path.join(self.valid_configs_dir, "all_valid.txt")
            with open(all_valid_file, 'w', encoding='utf-8') as f:
                f.write(f"# All Valid Configurations - TCP Test Passed\n")
                f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total valid configs: {self.stats['valid_configs']}\n\n")

                for protocol, configs in sorted(self.valid_configs.items()):
                    f.write(f"\n# {protocol.upper()} ({len(configs)} configs)\n")
                    for config in configs:
                        f.write(f"{config}\n")

            file_size = os.path.getsize(all_valid_file)
            print(f"✅ Saved all {self.stats['valid_configs']} valid configurations to {all_valid_file}")
            print(f"   File size: {file_size} bytes")
        except Exception as e:
            print(f"❌ Error saving combined valid configurations: {e}")

        # نمایش فهرست فایل‌های ایجاد شده
        print(f"\n{'='*30}")
        print("CREATED FILES:")
        print(f"{'='*30}")
        try:
            files = os.listdir(self.valid_configs_dir)
            for file in files:
                file_path = os.path.join(self.valid_configs_dir, file)
                if os.path.isfile(file_path):
                    size = os.path.getsize(file_path)
                    print(f"📁 {file} ({size} bytes)")
        except Exception as e:
            print(f"Error listing created files: {e}")

        print(f"\n✅ Successfully saved {total_saved} configurations in {len(self.valid_configs)} protocol files")

def main():
    title = "V2Ray Config TCP Connectivity Validator"
    print(title)
    print("=" * len(title))

    validator = ConnectivityValidator()
    validator.test_all_configs()

    print("\n🎉 Testing and saving completed successfully!")

if __name__ == "__main__":
    main()