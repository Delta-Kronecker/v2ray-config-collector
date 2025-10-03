package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

type TestResult string

const (
	ResultSuccess            TestResult = "success"
	ResultParseError         TestResult = "parse_error"
	ResultSyntaxError        TestResult = "syntax_error"
	ResultConnectionError    TestResult = "connection_error"
	ResultTimeout            TestResult = "timeout"
	ResultPortConflict       TestResult = "port_conflict"
	ResultInvalidConfig      TestResult = "invalid_config"
	ResultNetworkError       TestResult = "network_error"
	ResultHangTimeout        TestResult = "hang_timeout"
	ResultProcessKilled      TestResult = "process_killed"
	ResultUnsupportedProtocol TestResult = "unsupported_protocol"
)

type ProxyProtocol string

const (
	ProtocolShadowsocks ProxyProtocol = "shadowsocks"
	ProtocolVMess       ProxyProtocol = "vmess"
	ProtocolVLESS       ProxyProtocol = "vless"
)

type Config struct {
	XrayPath        string
	MaxWorkers      int
	Timeout         time.Duration
	BatchSize       int
	IncrementalSave bool
	DataDir         string
	ConfigDir       string
	LogDir          string
	StartPort       int
	EndPort         int
}

func NewDefaultConfig() *Config {
	dataDir := getEnvOrDefault("PROXY_DATA_DIR", "./data")
	configDir := getEnvOrDefault("PROXY_CONFIG_DIR", "./config")
	logDir := getEnvOrDefault("PROXY_LOG_DIR", "./log")

	return &Config{
		XrayPath:        getEnvOrDefault("XRAY_PATH", ""),
		MaxWorkers:      getEnvIntOrDefault("PROXY_MAX_WORKERS", 300),
		Timeout:         time.Duration(getEnvIntOrDefault("PROXY_TIMEOUT", 15)) * time.Second,
		BatchSize:       getEnvIntOrDefault("PROXY_BATCH_SIZE", 300),
		IncrementalSave: getEnvBoolOrDefault("PROXY_INCREMENTAL_SAVE", true),
		DataDir:         dataDir,
		ConfigDir:       configDir,
		LogDir:          logDir,
		StartPort:       getEnvIntOrDefault("PROXY_START_PORT", 10000),
		EndPort:         getEnvIntOrDefault("PROXY_END_PORT", 20000),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

type ProxyConfig struct {
	Protocol ProxyProtocol `json:"protocol"`
	Server   string        `json:"server"`
	Port     int           `json:"port"`
	Remarks  string        `json:"remarks"`

	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`

	UUID     string `json:"uuid,omitempty"`
	AlterID  int    `json:"alterId,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Encrypt  string `json:"encryption,omitempty"`

	Network     string `json:"network,omitempty"`
	TLS         string `json:"tls,omitempty"`
	SNI         string `json:"sni,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	HeaderType  string `json:"headerType,omitempty"`
	ServiceName string `json:"serviceName,omitempty"`

	RawConfig  map[string]interface{} `json:"raw_config,omitempty"`
	ConfigID   *int                   `json:"config_id,omitempty"`
	LineNumber *int                   `json:"line_number,omitempty"`
}

type TestResultData struct {
	Config       ProxyConfig `json:"config"`
	Result       TestResult  `json:"result"`
	TestTime     float64     `json:"test_time"`
	ResponseTime *float64    `json:"response_time,omitempty"`
	ErrorMessage string      `json:"error_message,omitempty"`
	ExternalIP   string      `json:"external_ip,omitempty"`
	ProxyPort    *int        `json:"proxy_port,omitempty"`
	BatchID      *int        `json:"batch_id,omitempty"`
}

type PortManager struct {
	startPort     int
	endPort       int
	availablePorts chan int
	usedPorts     sync.Map
	mu            sync.Mutex
	initialized   int32
}

func NewPortManager(startPort, endPort int) *PortManager {
	pm := &PortManager{
		startPort:      startPort,
		endPort:        endPort,
		availablePorts: make(chan int, endPort-startPort+1),
	}
	pm.initializePortPool()
	return pm
}

func (pm *PortManager) initializePortPool() {
	if !atomic.CompareAndSwapInt32(&pm.initialized, 0, 1) {
		return
	}

	log.Printf("Initializing port pool (%d-%d)...", pm.startPort, pm.endPort)
	availableCount := 0

	for port := pm.startPort; port <= pm.endPort; port++ {
		if pm.isPortAvailable(port) {
			select {
			case pm.availablePorts <- port:
				availableCount++
			default:
			}
		}
	}

	log.Printf("Port pool initialized with %d available ports", availableCount)
}

func (pm *PortManager) isPortAvailable(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

func (pm *PortManager) GetAvailablePort() (int, bool) {
	select {
	case port := <-pm.availablePorts:
		pm.usedPorts.Store(port, time.Now())
		return port, true
	case <-time.After(100 * time.Millisecond):
		return pm.findEmergencyPort(), true
	}
}

func (pm *PortManager) findEmergencyPort() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := 0; i < 100; i++ {
		port := rand.Intn(pm.endPort-pm.startPort+1) + pm.startPort
		if _, used := pm.usedPorts.Load(port); !used && pm.isPortAvailable(port) {
			pm.usedPorts.Store(port, time.Now())
			return port
		}
	}
	return 0
}

func (pm *PortManager) ReleasePort(port int) {
	pm.usedPorts.Delete(port)
	go func() {
		time.Sleep(50 * time.Millisecond)
		select {
		case pm.availablePorts <- port:
		default:
		}
	}()
}

func (pm *PortManager) cleanup() {
	pm.usedPorts.Range(func(key, value interface{}) bool {
		pm.usedPorts.Delete(key)
		return true
	})
}

type NetworkTester struct {
	timeout  time.Duration
	testURLs []string
	client   *http.Client
}

func NewNetworkTester(timeout time.Duration) *NetworkTester {
	return &NetworkTester{
		timeout: timeout,
		testURLs: []string{
			"http://httpbin.org/ip",
			"http://icanhazip.com",
			"http://ifconfig.me/ip",
			"http://api.ipify.org",
			"http://ipinfo.io/ip",
			"http://checkip.amazonaws.com",
			"https://httpbin.org/ip",
			"https://icanhazip.com",
		},
		client: &http.Client{Timeout: timeout},
	}
}

func (nt *NetworkTester) TestProxyConnection(proxyPort int) (bool, string, float64) {
	startTime := time.Now()

	if !nt.isProxyResponsive(proxyPort) {
		return false, "", time.Since(startTime).Seconds()
	}

	testCount := 4
	if len(nt.testURLs) < testCount {
		testCount = len(nt.testURLs)
	}

	shuffled := make([]string, len(nt.testURLs))
	copy(shuffled, nt.testURLs)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	for i := 0; i < testCount; i++ {
		success, ip, responseTime := nt.singleTest(proxyPort, shuffled[i])
		if success {
			return true, ip, responseTime
		}
	}

	return false, "", time.Since(startTime).Seconds()
}

func (nt *NetworkTester) isProxyResponsive(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (nt *NetworkTester) singleTest(proxyPort int, testURL string) (bool, string, float64) {
	startTime := time.Now()

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}

	transport := &http.Transport{
		Dial:                dialer.Dial,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		IdleConnTimeout:     time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   nt.timeout,
	}

	resp, err := client.Get(testURL)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "", time.Since(startTime).Seconds()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}

	responseTime := time.Since(startTime).Seconds()
	ipText := strings.TrimSpace(string(body))

	if strings.Contains(resp.Header.Get("Content-Type"), "json") {
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			if origin, ok := data["origin"].(string); ok {
				ipText = origin
			} else if ip, ok := data["ip"].(string); ok {
				ipText = ip
			}
		}
	}

	if net.ParseIP(ipText) != nil {
		return true, ipText, responseTime
	}

	return false, "", responseTime
}

type XrayConfigGenerator struct {
	xrayPath string
}

func NewXrayConfigGenerator(xrayPath string) *XrayConfigGenerator {
	if xrayPath == "" {
		xrayPath = findXrayExecutable()
	}
	return &XrayConfigGenerator{xrayPath: xrayPath}
}

func findXrayExecutable() string {
	paths := []string{"xray", "./xray", "/usr/local/bin/xray", "/usr/bin/xray"}

	for _, path := range paths {
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return "xray"
}

func (xcg *XrayConfigGenerator) ValidateXray() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, xcg.xrayPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("xray validation failed: %w", err)
	}

	log.Printf("Xray version: %s", strings.TrimSpace(string(output)))
	return nil
}

func (xcg *XrayConfigGenerator) GenerateConfig(config *ProxyConfig, listenPort int) (map[string]interface{}, error) {
	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "error",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  false,
					"ip":   "127.0.0.1",
				},
				"sniffing": map[string]interface{}{
					"enabled": false,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": string(config.Protocol),
				"settings": map[string]interface{}{},
				"streamSettings": map[string]interface{}{
					"sockopt": map[string]interface{}{
						"tcpKeepAliveInterval": 30,
						"tcpNoDelay":          true,
					},
				},
			},
		},
	}

	outbound := xrayConfig["outbounds"].([]map[string]interface{})[0]

	switch config.Protocol {
	case ProtocolShadowsocks:
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  config.Server,
					"port":     config.Port,
					"method":   config.Method,
					"password": config.Password,
					"level":    0,
				},
			},
		}

	case ProtocolVMess:
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": config.Server,
					"port":    config.Port,
					"users": []map[string]interface{}{
						{
							"id":       config.UUID,
							"alterId":  config.AlterID,
							"security": config.Cipher,
							"level":    0,
						},
					},
				},
			},
		}

	case ProtocolVLESS:
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": config.Server,
					"port":    config.Port,
					"users": []map[string]interface{}{
						{
							"id":         config.UUID,
							"flow":       config.Flow,
							"encryption": config.Encrypt,
							"level":      0,
						},
					},
				},
			},
		}
	}

	streamSettings := outbound["streamSettings"].(map[string]interface{})

	if config.Network != "" && config.Network != "tcp" {
		streamSettings["network"] = config.Network

		switch config.Network {
		case "ws":
			wsSettings := map[string]interface{}{}
			if config.Path != "" {
				wsSettings["path"] = config.Path
			}
			if config.Host != "" {
				wsSettings["headers"] = map[string]interface{}{"Host": config.Host}
			}
			streamSettings["wsSettings"] = wsSettings

		case "h2":
			h2Settings := map[string]interface{}{}
			if config.Path != "" {
				h2Settings["path"] = config.Path
			}
			if config.Host != "" {
				h2Settings["host"] = []string{config.Host}
			}
			streamSettings["httpSettings"] = h2Settings

		case "grpc":
			grpcSettings := map[string]interface{}{}
			if config.ServiceName != "" {
				grpcSettings["serviceName"] = config.ServiceName
			}
			streamSettings["grpcSettings"] = grpcSettings
		}
	}

	if config.TLS != "" {
		streamSettings["security"] = config.TLS
		tlsSettings := map[string]interface{}{
			"allowInsecure": true,
		}

		if config.SNI != "" {
			tlsSettings["serverName"] = config.SNI
		} else if config.Host != "" {
			tlsSettings["serverName"] = config.Host
		}

		if config.ALPN != "" {
			tlsSettings["alpn"] = strings.Split(config.ALPN, ",")
		}

		if config.Fingerprint != "" {
			tlsSettings["fingerprint"] = config.Fingerprint
		}

		if config.TLS == "tls" {
			streamSettings["tlsSettings"] = tlsSettings
		} else if config.TLS == "reality" {
			streamSettings["realitySettings"] = tlsSettings
		}
	}

	return xrayConfig, nil
}

type ProcessManager struct {
	processes sync.Map
	cleanup   int32
}

func NewProcessManager() *ProcessManager {
	return &ProcessManager{}
}

func (pm *ProcessManager) RegisterProcess(pid int, cmd *exec.Cmd) {
	pm.processes.Store(pid, cmd)
}

func (pm *ProcessManager) UnregisterProcess(pid int) {
	pm.processes.Delete(pid)
}

func (pm *ProcessManager) KillProcess(pid int) error {
	if atomic.LoadInt32(&pm.cleanup) == 1 {
		return nil
	}

	if value, ok := pm.processes.Load(pid); ok {
		if cmd, ok := value.(*exec.Cmd); ok {
			if cmd.Process != nil {
				if err := cmd.Process.Signal(syscall.SIGTERM); err == nil {
					done := make(chan error, 1)
					go func() {
						done <- cmd.Wait()
					}()

					select {
					case <-done:
					case <-time.After(200 * time.Millisecond):
						cmd.Process.Kill()
					}
				} else {
					cmd.Process.Kill()
				}
				pm.UnregisterProcess(pid)
				return nil
			}
		}
	}
	return fmt.Errorf("process not found")
}

func (pm *ProcessManager) Cleanup() {
	if !atomic.CompareAndSwapInt32(&pm.cleanup, 0, 1) {
		return
	}

	pm.processes.Range(func(key, value interface{}) bool {
		if pid, ok := key.(int); ok {
			pm.KillProcess(pid)
		}
		return true
	})
}

type ProxyTester struct {
	config            *Config
	portManager       *PortManager
	processManager    *ProcessManager
	networkTester     *NetworkTester
	configGenerator   *XrayConfigGenerator

	outputFiles       map[ProxyProtocol]*os.File
	urlFiles          map[ProxyProtocol]*os.File
	generalJSONFile   *os.File
	generalURLFile    *os.File

	stats             sync.Map
	resultsMu         sync.Mutex
}

func NewProxyTester(config *Config) (*ProxyTester, error) {
	pt := &ProxyTester{
		config:          config,
		portManager:     NewPortManager(config.StartPort, config.EndPort),
		processManager:  NewProcessManager(),
		networkTester:   NewNetworkTester(config.Timeout),
		configGenerator: NewXrayConfigGenerator(config.XrayPath),
		outputFiles:     make(map[ProxyProtocol]*os.File),
		urlFiles:        make(map[ProxyProtocol]*os.File),
	}

	if err := pt.configGenerator.ValidateXray(); err != nil {
		return nil, err
	}

	pt.initStats()

	if config.IncrementalSave {
		if err := pt.setupIncrementalSave(); err != nil {
			log.Printf("Warning: Failed to setup incremental save: %v", err)
			pt.config.IncrementalSave = false
		}
	}

	return pt, nil
}

func (pt *ProxyTester) initStats() {
	protocols := []ProxyProtocol{ProtocolShadowsocks, ProtocolVMess, ProtocolVLESS}
	for _, protocol := range protocols {
		pt.stats.Store(protocol, map[string]*int64{
			"total":   new(int64),
			"success": new(int64),
			"failed":  new(int64),
		})
	}
	pt.stats.Store("overall", map[string]*int64{
		"total":             new(int64),
		"success":           new(int64),
		"failed":            new(int64),
		"parse_errors":      new(int64),
		"syntax_errors":     new(int64),
		"connection_errors": new(int64),
		"timeouts":          new(int64),
		"network_errors":    new(int64),
	})
}

func (pt *ProxyTester) setupIncrementalSave() error {
	if err := os.MkdirAll(filepath.Join(pt.config.DataDir, "working_json"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(pt.config.DataDir, "working_url"), 0755); err != nil {
		return err
	}

	protocols := map[ProxyProtocol]string{
		ProtocolShadowsocks: "shadowsocks",
		ProtocolVMess:       "vmess",
		ProtocolVLESS:       "vless",
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	for protocol, name := range protocols {
		jsonFile, err := os.Create(filepath.Join(pt.config.DataDir, "working_json", fmt.Sprintf("working_%s.txt", name)))
		if err != nil {
			return err
		}

		jsonFile.WriteString(fmt.Sprintf("# Working %s Configurations (JSON Format)\n", strings.ToUpper(name)))
		jsonFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
		jsonFile.WriteString("# Format: Each line contains one working configuration in JSON\n\n")
		pt.outputFiles[protocol] = jsonFile

		urlFile, err := os.Create(filepath.Join(pt.config.DataDir, "working_url", fmt.Sprintf("working_%s_urls.txt", name)))
		if err != nil {
			return err
		}

		urlFile.WriteString(fmt.Sprintf("# Working %s Configurations (URL Format)\n", strings.ToUpper(name)))
		urlFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
		urlFile.WriteString("# Format: Each line contains one working configuration as URL\n\n")
		pt.urlFiles[protocol] = urlFile
	}

	generalJSONFile, err := os.Create(filepath.Join(pt.config.DataDir, "working_json", "working_all_configs.txt"))
	if err != nil {
		return err
	}
	generalJSONFile.WriteString("# All Working Configurations (JSON Format)\n")
	generalJSONFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
	generalJSONFile.WriteString("# Format: Each line contains one working configuration in JSON\n")
	generalJSONFile.WriteString("# Protocols: Shadowsocks, VMess, VLESS\n\n")
	pt.generalJSONFile = generalJSONFile

	generalURLFile, err := os.Create(filepath.Join(pt.config.DataDir, "working_url", "working_all_urls.txt"))
	if err != nil {
		return err
	}
	generalURLFile.WriteString("# All Working Configurations (URL Format)\n")
	generalURLFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
	generalURLFile.WriteString("# Format: Each line contains one working configuration as URL\n")
	generalURLFile.WriteString("# Protocols: Shadowsocks, VMess, VLESS\n\n")
	pt.generalURLFile = generalURLFile

	log.Println("Incremental save files initialized")
	return nil
}

func (pt *ProxyTester) LoadConfigsFromJSON(filePath string, protocol ProxyProtocol) ([]ProxyConfig, error) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file not found: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var configs []ProxyConfig
	seenHashes := make(map[string]bool)

	log.Printf("Loading %s configurations from: %s", protocol, filePath)

	switch protocol {
	case ProtocolShadowsocks:
		configs, err = pt.loadShadowsocksConfigs(file, seenHashes)
	case ProtocolVMess:
		configs, err = pt.loadVMessConfigs(file, seenHashes)
	case ProtocolVLESS:
		configs, err = pt.loadVLessConfigs(file, seenHashes)
	}

	if err != nil {
		return nil, err
	}

	log.Printf("Loaded %d unique %s configurations", len(configs), protocol)
	return configs, nil
}

func (pt *ProxyTester) loadShadowsocksConfigs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type SSConfig struct {
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		Password   string `json:"password"`
		Method     string `json:"method"`
		Name       string `json:"name"`
	}

	var data []SSConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	var configs []ProxyConfig
	for _, configData := range data {
		config := ProxyConfig{
			Protocol: ProtocolShadowsocks,
			Server:   configData.Server,
			Port:     configData.ServerPort,
			Method:   configData.Method,
			Password: configData.Password,
			Remarks:  configData.Name,
			Network:  "tcp",
		}

		if pt.isValidConfig(&config) {
			hash := pt.getConfigHash(&config)
			if !seenHashes[hash] {
				seenHashes[hash] = true
				configs = append(configs, config)
			}
		}
	}

	return configs, nil
}

func (pt *ProxyTester) loadVMessConfigs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type VMConfig struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		ID       string `json:"id"`
		Security string `json:"security"`
		Network  string `json:"network"`
		Name     string `json:"name"`
		AlterId  string `json:"aid"`
		Type     string `json:"type"`
		Path     string `json:"path"`
		Host     string `json:"host"`
		TLS      string `json:"tls"`
		SNI      string `json:"sni"`
	}

	var data []VMConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	var configs []ProxyConfig
	for _, configData := range data {
		alterId := 0
		if configData.AlterId != "" {
			if aid, err := strconv.Atoi(configData.AlterId); err == nil {
				alterId = aid
			}
		}

		config := ProxyConfig{
			Protocol:   ProtocolVMess,
			Server:     configData.Address,
			Port:       configData.Port,
			UUID:       configData.ID,
			AlterID:    alterId,
			Cipher:     configData.Security,
			Network:    configData.Network,
			TLS:        configData.TLS,
			SNI:        configData.SNI,
			Path:       configData.Path,
			Host:       configData.Host,
			Remarks:    configData.Name,
			HeaderType: configData.Type,
		}

		if pt.isValidConfig(&config) {
			hash := pt.getConfigHash(&config)
			if !seenHashes[hash] {
				seenHashes[hash] = true
				configs = append(configs, config)
			}
		}
	}

	return configs, nil
}

func (pt *ProxyTester) loadVLessConfigs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type VLConfig struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Host    string `json:"host"`
		Path    string `json:"path"`
		TLS     string `json:"tls"`
		SNI     string `json:"sni"`
	}

	var data []VLConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, err
	}

	var configs []ProxyConfig
	for _, configData := range data {
		config := ProxyConfig{
			Protocol: ProtocolVLESS,
			Server:   configData.Address,
			Port:     configData.Port,
			UUID:     configData.ID,
			Network:  configData.Type,
			TLS:      configData.TLS,
			SNI:      configData.SNI,
			Path:     configData.Path,
			Host:     configData.Host,
			Remarks:  configData.Name,
			Encrypt:  "none",
		}

		if pt.isValidConfig(&config) {
			hash := pt.getConfigHash(&config)
			if !seenHashes[hash] {
				seenHashes[hash] = true
				configs = append(configs, config)
			}
		}
	}

	return configs, nil
}

func (pt *ProxyTester) isValidUUID(uuid string) bool {
	re := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return re.MatchString(uuid)
}

func (pt *ProxyTester) isValidConfig(config *ProxyConfig) bool {
	if config.Server == "" || config.Port <= 0 || config.Port > 65535 {
		return false
	}

	switch config.Protocol {
	case ProtocolShadowsocks:
		return config.Method != "" && config.Password != ""
	case ProtocolVMess:
		return pt.isValidUUID(config.UUID)
	case ProtocolVLESS:
		return pt.isValidUUID(config.UUID)
	}

	return false
}

func (pt *ProxyTester) getConfigHash(config *ProxyConfig) string {
	var hashStr string
	switch config.Protocol {
	case ProtocolShadowsocks:
		hashStr = fmt.Sprintf("ss://%s:%d:%s:%s", config.Server, config.Port, config.Method, config.Password)
	case ProtocolVMess:
		hashStr = fmt.Sprintf("vmess://%s:%d:%s:%d:%s", config.Server, config.Port, config.UUID, config.AlterID, config.Network)
	case ProtocolVLESS:
		hashStr = fmt.Sprintf("vless://%s:%d:%s:%s", config.Server, config.Port, config.UUID, config.Network)
	}

	hash := md5.Sum([]byte(hashStr))
	return fmt.Sprintf("%x", hash)
}

func (pt *ProxyTester) TestSingleConfig(config *ProxyConfig, batchID int) *TestResultData {
	startTime := time.Now()
	var proxyPort int
	var process *exec.Cmd
	var configFile string

	result := &TestResultData{
		Config:  *config,
		BatchID: &batchID,
	}

	defer func() {
		result.TestTime = time.Since(startTime).Seconds()

		if process != nil && process.Process != nil {
			pt.processManager.KillProcess(process.Process.Pid)
		}
		if configFile != "" {
			os.Remove(configFile)
		}
		if proxyPort > 0 {
			pt.portManager.ReleasePort(proxyPort)
		}
	}()

	var ok bool
	proxyPort, ok = pt.portManager.GetAvailablePort()
	if !ok || proxyPort == 0 {
		result.Result = ResultPortConflict
		return result
	}
	result.ProxyPort = &proxyPort

	xrayConfig, err := pt.configGenerator.GenerateConfig(config, proxyPort)
	if err != nil {
		result.Result = ResultInvalidConfig
		result.ErrorMessage = err.Error()
		return result
	}

	configFile, err = pt.writeConfigToTempFile(xrayConfig)
	if err != nil {
		result.Result = ResultInvalidConfig
		result.ErrorMessage = err.Error()
		return result
	}

	if err := pt.testConfigSyntax(configFile); err != nil {
		result.Result = ResultSyntaxError
		result.ErrorMessage = err.Error()
		return result
	}

	process, err = pt.startXrayProcess(configFile)
	if err != nil {
		result.Result = ResultConnectionError
		result.ErrorMessage = err.Error()
		return result
	}

	pt.processManager.RegisterProcess(process.Process.Pid, process)

	time.Sleep(time.Second)

	if process.ProcessState != nil && process.ProcessState.Exited() {
		result.Result = ResultConnectionError
		result.ErrorMessage = "Xray process terminated"
		return result
	}

	success, externalIP, responseTime := pt.networkTester.TestProxyConnection(proxyPort)
	if success {
		result.Result = ResultSuccess
		result.ExternalIP = externalIP
		result.ResponseTime = &responseTime

		if pt.config.IncrementalSave {
			pt.saveConfigImmediately(result)
		}

		log.Printf("SUCCESS: %s://%s:%d (%.3fs)", config.Protocol, config.Server, config.Port, responseTime)
	} else {
		result.Result = ResultNetworkError
		result.ErrorMessage = "Network test failed"
	}

	return result
}

func (pt *ProxyTester) writeConfigToTempFile(config map[string]interface{}) (string, error) {
	tmpFile, err := os.CreateTemp("", "xray-config-*.json")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

func (pt *ProxyTester) testConfigSyntax(configFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, pt.configGenerator.xrayPath, "run", "-test", "-config", configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("syntax test failed: %s", string(output))
	}

	return nil
}

func (pt *ProxyTester) startXrayProcess(configFile string) (*exec.Cmd, error) {
	cmd := exec.Command(pt.configGenerator.xrayPath, "run", "-config", configFile)

	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	return cmd, nil
}

func (pt *ProxyTester) saveConfigImmediately(result *TestResultData) {
	if result.Result != ResultSuccess {
		return
	}

	protocol := result.Config.Protocol
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if file, ok := pt.outputFiles[protocol]; ok {
		configLine := pt.createWorkingConfigLine(result)
		fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s\n",
			timestamp, *result.ResponseTime, result.ExternalIP)
		fmt.Fprintf(file, "%s\n\n", configLine)
		file.Sync()
	}

	if file, ok := pt.urlFiles[protocol]; ok {
		configURL := pt.createConfigURL(result)
		fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s\n",
			timestamp, *result.ResponseTime, result.ExternalIP)
		fmt.Fprintf(file, "%s\n\n", configURL)
		file.Sync()
	}

	if pt.generalJSONFile != nil {
		configLine := pt.createWorkingConfigLine(result)
		fmt.Fprintf(pt.generalJSONFile, "# [%s] Tested at: %s | Response: %.3fs | IP: %s\n",
			strings.ToUpper(string(protocol)), timestamp, *result.ResponseTime, result.ExternalIP)
		fmt.Fprintf(pt.generalJSONFile, "%s\n\n", configLine)
		pt.generalJSONFile.Sync()
	}

	if pt.generalURLFile != nil {
		configURL := pt.createConfigURL(result)
		fmt.Fprintf(pt.generalURLFile, "# [%s] Tested at: %s | Response: %.3fs | IP: %s\n",
			strings.ToUpper(string(protocol)), timestamp, *result.ResponseTime, result.ExternalIP)
		fmt.Fprintf(pt.generalURLFile, "%s\n\n", configURL)
		pt.generalURLFile.Sync()
	}
}

func (pt *ProxyTester) createWorkingConfigLine(result *TestResultData) string {
	config := &result.Config

	data := map[string]interface{}{
		"protocol":    string(config.Protocol),
		"server":      config.Server,
		"port":        config.Port,
		"network":     config.Network,
		"tls":         config.TLS,
		"remarks":     config.Remarks,
		"test_time":   result.ResponseTime,
		"external_ip": result.ExternalIP,
	}

	switch config.Protocol {
	case ProtocolShadowsocks:
		data["method"] = config.Method
		data["password"] = config.Password
	case ProtocolVMess:
		data["uuid"] = config.UUID
		data["alterId"] = config.AlterID
		data["cipher"] = config.Cipher
		data["path"] = config.Path
		data["host"] = config.Host
		data["sni"] = config.SNI
	case ProtocolVLESS:
		data["uuid"] = config.UUID
		data["flow"] = config.Flow
		data["encryption"] = config.Encrypt
		data["path"] = config.Path
		data["host"] = config.Host
		data["sni"] = config.SNI
	}

	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func (pt *ProxyTester) createConfigURL(result *TestResultData) string {
	config := &result.Config

	switch config.Protocol {
	case ProtocolShadowsocks:
		auth := fmt.Sprintf("%s:%s", config.Method, config.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(auth))
		remarks := url.QueryEscape(config.Remarks)
		if remarks == "" {
			remarks = fmt.Sprintf("SS-%s", config.Server)
		}
		return fmt.Sprintf("ss://%s@%s:%d#%s", authB64, config.Server, config.Port, remarks)

	case ProtocolVMess:
		vmessConfig := map[string]interface{}{
			"v":    "2",
			"ps":   config.Remarks,
			"add":  config.Server,
			"port": strconv.Itoa(config.Port),
			"id":   config.UUID,
			"aid":  strconv.Itoa(config.AlterID),
			"scy":  config.Cipher,
			"net":  config.Network,
			"type": config.HeaderType,
			"host": config.Host,
			"path": config.Path,
			"tls":  config.TLS,
			"sni":  config.SNI,
			"alpn": config.ALPN,
		}
		if vmessConfig["ps"] == "" {
			vmessConfig["ps"] = fmt.Sprintf("VMess-%s", config.Server)
		}

		jsonBytes, _ := json.Marshal(vmessConfig)
		vmessB64 := base64.StdEncoding.EncodeToString(jsonBytes)
		return fmt.Sprintf("vmess://%s", vmessB64)

	case ProtocolVLESS:
		params := url.Values{}
		if config.Encrypt != "" && config.Encrypt != "none" {
			params.Add("encryption", config.Encrypt)
		}
		if config.Flow != "" {
			params.Add("flow", config.Flow)
		}
		if config.TLS != "" {
			params.Add("security", config.TLS)
		}
		if config.Network != "" && config.Network != "tcp" {
			params.Add("type", config.Network)
		}
		if config.Host != "" {
			params.Add("host", config.Host)
		}
		if config.Path != "" {
			params.Add("path", config.Path)
		}
		if config.SNI != "" {
			params.Add("sni", config.SNI)
		}
		if config.ALPN != "" {
			params.Add("alpn", config.ALPN)
		}
		if config.ServiceName != "" {
			params.Add("serviceName", config.ServiceName)
		}
		if config.Fingerprint != "" {
			params.Add("fp", config.Fingerprint)
		}

		query := ""
		if len(params) > 0 {
			query = "?" + params.Encode()
		}

		remarks := url.QueryEscape(config.Remarks)
		if remarks == "" {
			remarks = fmt.Sprintf("VLESS-%s", config.Server)
		}

		return fmt.Sprintf("vless://%s@%s:%d%s#%s", config.UUID, config.Server, config.Port, query, remarks)
	}

	return fmt.Sprintf("%s://%s:%d", config.Protocol, config.Server, config.Port)
}

func (pt *ProxyTester) updateStats(result *TestResultData) {
	if protocolStats, ok := pt.stats.Load(result.Config.Protocol); ok {
		stats := protocolStats.(map[string]*int64)
		atomic.AddInt64(stats["total"], 1)
		if result.Result == ResultSuccess {
			atomic.AddInt64(stats["success"], 1)
		} else {
			atomic.AddInt64(stats["failed"], 1)
		}
	}

	if overallStats, ok := pt.stats.Load("overall"); ok {
		stats := overallStats.(map[string]*int64)
		atomic.AddInt64(stats["total"], 1)

		switch result.Result {
		case ResultSuccess:
			atomic.AddInt64(stats["success"], 1)
		case ResultParseError:
			atomic.AddInt64(stats["parse_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultSyntaxError:
			atomic.AddInt64(stats["syntax_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultConnectionError:
			atomic.AddInt64(stats["connection_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultTimeout:
			atomic.AddInt64(stats["timeouts"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultNetworkError:
			atomic.AddInt64(stats["network_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		default:
			atomic.AddInt64(stats["failed"], 1)
		}
	}
}

func (pt *ProxyTester) TestConfigs(configs []ProxyConfig, batchID int) []*TestResultData {
	if len(configs) == 0 {
		return nil
	}

	log.Printf("Testing batch %d with %d configurations...", batchID, len(configs))

	maxWorkers := pt.config.MaxWorkers
	if len(configs) < maxWorkers {
		maxWorkers = len(configs)
	}

	configChan := make(chan ProxyConfig, len(configs))
	resultChan := make(chan *TestResultData, len(configs))

	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for config := range configChan {
				result := pt.TestSingleConfig(&config, batchID)
				pt.updateStats(result)
				resultChan <- result
			}
		}()
	}

	for _, config := range configs {
		configChan <- config
	}
	close(configChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var results []*TestResultData
	successCount := 0

	for result := range resultChan {
		results = append(results, result)
		if result.Result == ResultSuccess {
			successCount++
		}
	}

	log.Printf("Batch %d completed: %d/%d successful (%.1f%%)",
		batchID, successCount, len(configs), float64(successCount)/float64(len(configs))*100)

	return results
}

func (pt *ProxyTester) RunTests(configs []ProxyConfig) []*TestResultData {
	if len(configs) == 0 {
		log.Println("No configurations to test")
		return nil
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, cleaning up...")
		pt.Cleanup()
		os.Exit(0)
	}()

	totalConfigs := len(configs)
	log.Printf("Starting comprehensive proxy testing for %d configurations", totalConfigs)
	log.Printf("Settings: %d workers, %v timeout, batch size: %d", pt.config.MaxWorkers, pt.config.Timeout, pt.config.BatchSize)

	var allResults []*TestResultData

	for batchIdx := 0; batchIdx < totalConfigs; batchIdx += pt.config.BatchSize {
		end := batchIdx + pt.config.BatchSize
		if end > totalConfigs {
			end = totalConfigs
		}

		batch := configs[batchIdx:end]
		batchID := (batchIdx / pt.config.BatchSize) + 1

		log.Printf("Processing batch %d (%d configs)...", batchID, len(batch))

		batchResults := pt.TestConfigs(batch, batchID)
		allResults = append(allResults, batchResults...)

		pt.saveResults(allResults)

		if end < totalConfigs {
			time.Sleep(500 * time.Millisecond)
		}
	}

	pt.printFinalSummary(allResults)
	return allResults
}

func (pt *ProxyTester) saveResults(results []*TestResultData) {
	if err := os.MkdirAll(pt.config.LogDir, 0755); err != nil {
		log.Printf("Failed to create log directory: %v", err)
		return
	}

	file, err := os.Create(filepath.Join(pt.config.LogDir, "test_results.json"))
	if err != nil {
		log.Printf("Failed to save results: %v", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(results)
}

func (pt *ProxyTester) printFinalSummary(results []*TestResultData) {
	successCount := 0
	totalCount := len(results)
	var successTimes []float64

	for _, result := range results {
		if result.Result == ResultSuccess {
			successCount++
			if result.ResponseTime != nil {
				successTimes = append(successTimes, *result.ResponseTime)
			}
		}
	}

	log.Println("=" + strings.Repeat("=", 59))
	log.Println("FINAL TESTING SUMMARY")
	log.Println("=" + strings.Repeat("=", 59))
	log.Printf("Total configurations tested: %d", totalCount)
	log.Printf("Successful connections: %d", successCount)
	log.Printf("Failed connections: %d", totalCount-successCount)
	if totalCount > 0 {
		log.Printf("Success rate: %.2f%%", float64(successCount)/float64(totalCount)*100)
	}

	log.Println("\nProtocol Breakdown:")
	protocols := []ProxyProtocol{ProtocolShadowsocks, ProtocolVMess, ProtocolVLESS}
	for _, protocol := range protocols {
		if statsValue, ok := pt.stats.Load(protocol); ok {
			stats := statsValue.(map[string]*int64)
			total := atomic.LoadInt64(stats["total"])
			success := atomic.LoadInt64(stats["success"])
			if total > 0 {
				successPct := float64(success) / float64(total) * 100
				log.Printf("  %-12s: %4d/%4d (%.1f%%)",
					strings.ToUpper(string(protocol)), success, total, successPct)
			}
		}
	}

	if len(successTimes) > 0 {
		var sum float64
		min, max := successTimes[0], successTimes[0]

		for _, t := range successTimes {
			sum += t
			if t < min {
				min = t
			}
			if t > max {
				max = t
			}
		}

		avg := sum / float64(len(successTimes))
		log.Println("\nResponse Times (successful only):")
		log.Printf("  Average: %.3fs", avg)
		log.Printf("  Minimum: %.3fs", min)
		log.Printf("  Maximum: %.3fs", max)
	}

	log.Println("=" + strings.Repeat("=", 59))
}

func (pt *ProxyTester) Cleanup() {
	for _, file := range pt.outputFiles {
		if file != nil {
			file.Close()
		}
	}
	for _, file := range pt.urlFiles {
		if file != nil {
			file.Close()
		}
	}

	if pt.generalJSONFile != nil {
		pt.generalJSONFile.Close()
	}
	if pt.generalURLFile != nil {
		pt.generalURLFile.Close()
	}

	pt.processManager.Cleanup()
	pt.portManager.cleanup()
}

func setupDirectories(config *Config) error {
	dirs := []string{
		config.DataDir,
		config.LogDir,
		filepath.Join(config.DataDir, "working_json"),
		filepath.Join(config.DataDir, "working_url"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

func main() {
	config := NewDefaultConfig()

	if err := setupDirectories(config); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}

	tester, err := NewProxyTester(config)
	if err != nil {
		log.Fatalf("Failed to initialize tester: %v", err)
	}
	defer tester.Cleanup()

	var allConfigs []ProxyConfig

	configFiles := map[ProxyProtocol]string{
		ProtocolShadowsocks: "../data/deduplicated_urls/ss.json",
		ProtocolVMess:       "../data/deduplicated_urls/vmess.json",
		ProtocolVLESS:       "../data/deduplicated_urls/vless.json",
	}

	for protocol, filePath := range configFiles {
		if _, err := os.Stat(filePath); err == nil {
			configs, err := tester.LoadConfigsFromJSON(filePath, protocol)
			if err != nil {
				log.Printf("Failed to load %s configs: %v", protocol, err)
			} else {
				allConfigs = append(allConfigs, configs...)
			}
		} else {
			log.Printf("Config file not found: %s", filePath)
		}
	}

	if len(allConfigs) == 0 {
		log.Println("No valid configurations found to test")
		return
	}

	log.Printf("Total unique configurations for testing: %d", len(allConfigs))

	results := tester.RunTests(allConfigs)

	workingConfigs := 0
	for _, result := range results {
		if result.Result == ResultSuccess {
			workingConfigs++
		}
	}

	if workingConfigs > 0 {
		log.Printf("\nWorking configurations saved to:")
		log.Printf("  JSON: %s/working_json/working_*.txt", config.DataDir)
		log.Printf("  URL: %s/working_url/working_*_urls.txt", config.DataDir)
		log.Printf("  All configs (JSON): %s/working_json/working_all_configs.txt", config.DataDir)
		log.Printf("  All configs (URL): %s/working_url/working_all_urls.txt", config.DataDir)
	} else {
		log.Println("No working configurations found")
	}
}
