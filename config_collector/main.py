from get_source import get_source
from find_url_config import find_url_config
from decode_base64 import decode_base64
from find_url_from_decoded import find_url_from_decoded
from reformat import process_protocol_files
from config_parser import ConfigParser
from config_deduplicator import ConfigDeduplicator


get_source()


find_url_config()


decode_base64()


find_url_from_decoded()


protocols = ['ss', 'vmess', 'vless', 'trojan', 'ssr', 'hy', 'tuic']
for protocol in protocols:
    process_protocol_files(protocol)


parser = ConfigParser()
parser.process_all_files()


deduplicator = ConfigDeduplicator()
deduplicator.process_all_protocols()