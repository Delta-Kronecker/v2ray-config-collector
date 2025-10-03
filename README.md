 # Xray Proxy Configuration Collector and Tester
 
 A comprehensive tool for collecting, processing, and testing proxy configurations for Xray. This project automates the discovery and validation of working proxy servers, making it easier to find reliable proxies for bypassing internet restrictions.
 
 ## Iran-Specific Testing Results (Manually update)
 
 The configurations in `working_all_urls.txt` have been tested for functionality within Iran.
 The test results are available at:
 
 **Iran Test Results**: 
 - [test_in_iran.txt](https://raw.githubusercontent.com/Delta-Kronecker/Xray/refs/heads/main/test_in_iran.txt)

 ### All Protocols Combined (automatic update every 12 hour)
 - **All Working URLs**: 
 - [working_all_urls.txt](https://raw.githubusercontent.com/Delta-Kronecker/Xray/refs/heads/main/data/working_url/working_all_urls.txt)
 
 ### Protocol-Specific Files (update every 12 hour)
 - **Shadowsocks**: 
 - [working_shadowsocks_urls.txt](https://raw.githubusercontent.com/Delta-Kronecker/Xray/refs/heads/main/data/working_url/working_shadowsocks_urls.txt)
 - **VMess**: 
 - [working_vmess_urls.txt](https://raw.githubusercontent.com/Delta-Kronecker/Xray/refs/heads/main/data/working_url/working_vmess_urls.txt)
 - **VLESS**: 
 - [working_vless_urls.txt](https://raw.githubusercontent.com/Delta-Kronecker/Xray/refs/heads/main/data/working_url/working_vless_urls.txt)
 


 ## Usage
 
 ### Collecting Configurations
 Run the Python collector to gather and process proxy configurations:
 ```bash
 cd config_collector
 python main.py
 ```
 
 This will:
 - Fetch data from various sources
 - Decode base64 encoded configurations
 - Parse and validate configurations
 - Remove duplicates
 - Save processed configs to JSON files
 
 ### Testing Configurations
 Run the Go tester to validate collected configurations:
 ```bash
 cd xray_test
 ./proxy-tester
 ```
 
 The tester will:
 - Load JSON configuration files
 - Generate Xray config files for each proxy
 - Test connectivity using HTTP requests
 - Save working configurations to output files
 

 ## Working Configurations
 
 The following files contain validated, working proxy configurations:
 


 ## Project Structure
 
 ```
 Xray-main/
 ├── config_collector/          # Python collection and processing scripts
 │   ├── main.py               # Main collection orchestrator
 │   ├── get_source.py         # Source data fetching
 │   ├── find_url_config.py    # URL extraction
 │   ├── decode_base64.py      # Base64 decoding
 │   ├── reformat.py           # Protocol-specific formatting
 │   ├── config_parser.py      # Configuration parsing
 │   ├── config_deduplicator.py # Duplicate removal
 │   └── find_url_from_decoded.py # Additional URL extraction
 ├── xray_test/                # Go testing framework
 │   ├── proxy-tester.go       # Main testing application
 │   ├── go.mod
 │   └── go.sum
 ├── data/
 │   └── working_url/          # Validated configuration files
 │       ├── working_all_urls.txt
 │       ├── working_shadowsocks_urls.txt
 │       ├── working_vmess_urls.txt
 │       └── working_vless_urls.txt
 ├── test_in_iran.txt          # Iran-specific test results
 └── README.md
 ```
 
 ## How It Works
 
 1. **Collection Phase**: The Python scripts fetch proxy configurations from various online sources and APIs
 2. **Processing Phase**: Configurations are decoded, parsed, validated, and deduplicated
 3. **Testing Phase**: The Go application loads processed configs and tests each one by:
    - Generating Xray configuration files
    - Starting Xray processes on unique ports
    - Making HTTP requests through the proxy to verify connectivity
    - Recording response times and success/failure status
 4. **Output Phase**: Working configurations are saved to categorized files for easy access
 
