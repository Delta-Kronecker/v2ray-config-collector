package main

import (
	"bufio"
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
	"runtime"
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
	ProtocolShadowsocks   ProxyProtocol = "shadowsocks"
	ProtocolShadowsocksR  ProxyProtocol = "shadowsocksr"
	ProtocolVMess         ProxyProtocol = "vmess"
	ProtocolVLESS         ProxyProtocol = "vless"
	ProtocolTrojan        ProxyProtocol = "trojan"
	ProtocolHysteria      ProxyProtocol = "hysteria"
	ProtocolHysteria2     ProxyProtocol = "hysteria2"
	ProtocolTUIC          ProxyProtocol = "tuic"
)

type GeoIPInfo struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	CountryFlag string `json:"country_flag"`
}

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
	dataDir := getEnvOrDefault("PROXY_DATA_DIR", "../data")
	configDir := getEnvOrDefault("PROXY_CONFIG_DIR", "../config")
	logDir := getEnvOrDefault("PROXY_LOG_DIR", "../log")

	return &Config{
		XrayPath:        getEnvOrDefault("XRAY_PATH", ""),
		MaxWorkers:      getEnvIntOrDefault("PROXY_MAX_WORKERS", 300),
		Timeout:         time.Duration(getEnvIntOrDefault("PROXY_TIMEOUT", 5)) * time.Second,
		BatchSize:       getEnvIntOrDefault("PROXY_BATCH_SIZE", 600),
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

	Protocol_Param string `json:"protocol_param,omitempty"`
	Obfs           string `json:"obfs,omitempty"`
	ObfsParam      string `json:"obfs_param,omitempty"`

	UpMbps         int    `json:"up_mbps,omitempty"`
	DownMbps       int    `json:"down_mbps,omitempty"`
	AuthStr        string `json:"auth_str,omitempty"`
	Insecure       bool   `json:"insecure,omitempty"`
	CongestionCtrl string `json:"congestion_control,omitempty"`

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
	CountryCode  string      `json:"country_code,omitempty"`
	CountryName  string      `json:"country_name,omitempty"`
	CountryFlag  string      `json:"country_flag,omitempty"`
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

// GetAvailablePort returns (port, true) on success, (0, false) if no port available.
func (pm *PortManager) GetAvailablePort() (int, bool) {
	select {
	case port := <-pm.availablePorts:
		pm.usedPorts.Store(port, time.Now())
		return port, true
	case <-time.After(100 * time.Millisecond):
		if port, ok := pm.findEmergencyPort(); ok {
			return port, true
		}
		return 0, false
	}
}

// findEmergencyPort tries to find a random available port in the range.
// returns (port, true) if found, (0, false) otherwise
func (pm *PortManager) findEmergencyPort() (int, bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := 0; i < 200; i++ {
		port := rand.Intn(pm.endPort-pm.startPort+1) + pm.startPort
		if _, used := pm.usedPorts.Load(port); !used && pm.isPortAvailable(port) {
			pm.usedPorts.Store(port, time.Now())
			return port, true
		}
	}
	return 0, false
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

// Provider 1: ip-api.com
func getGeoInfoFromIPAPI(ip string, client *http.Client) (*GeoIPInfo, error) {
	apiURL := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode", ip)
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("ip-api.com request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status      string `json:"status"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ip-api.com JSON decode failed: %w", err)
	}

	if result.Status != "success" {
		return nil, fmt.Errorf("ip-api.com lookup failed: %s", result.Message)
	}

	return &GeoIPInfo{
		CountryCode: result.CountryCode,
		CountryName: result.Country,
		CountryFlag: countryCodeToFlag(result.CountryCode),
	}, nil
}

// Provider 2: ipwho.is
func getGeoInfoFromIPWho(ip string, client *http.Client) (*GeoIPInfo, error) {
	apiURL := fmt.Sprintf("http://ipwho.is/%s", ip)
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("ipwho.is request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success     bool   `json:"success"`
		Message     string `json:"message"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ipwho.is JSON decode failed: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("ipwho.is lookup failed: %s", result.Message)
	}

	return &GeoIPInfo{
		CountryCode: result.CountryCode,
		CountryName: result.Country,
		CountryFlag: countryCodeToFlag(result.CountryCode),
	}, nil
}

// Provider 3: freegeoip.app
func getGeoInfoFromFreeGeoIP(ip string, client *http.Client) (*GeoIPInfo, error) {
	apiURL := fmt.Sprintf("https://freegeoip.app/json/%s", ip)
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("freegeoip.app request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		CountryCode string `json:"country_code"`
		CountryName string `json:"country_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("freegeoip.app JSON decode failed: %w", err)
	}

	if result.CountryCode == "" {
		return nil, fmt.Errorf("freegeoip.app lookup failed: empty country code")
	}

	return &GeoIPInfo{
		CountryCode: result.CountryCode,
		CountryName: result.CountryName,
		CountryFlag: countryCodeToFlag(result.CountryCode),
	}, nil
}

// Provider 4: ipinfo.io
func getGeoInfoFromIPInfo(ip string, client *http.Client) (*GeoIPInfo, error) {
	apiURL := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("ipinfo.io request failed: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Country string `json:"country"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("ipinfo.io JSON decode failed: %w", err)
	}

	if result.Country == "" {
		return nil, fmt.Errorf("ipinfo.io lookup failed: empty country code")
	}

	return &GeoIPInfo{
		CountryCode: result.Country,
		CountryName: "", // Name not available in this fallback
		CountryFlag: countryCodeToFlag(result.Country),
	}, nil
}

func (nt *NetworkTester) GetCountryInfo(ip string) (*GeoIPInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	providers := []func(string, *http.Client) (*GeoIPInfo, error){
		getGeoInfoFromIPAPI,
		getGeoInfoFromIPWho,
		getGeoInfoFromFreeGeoIP,
		getGeoInfoFromIPInfo,
	}

	for i, provider := range providers {
		geoInfo, err := provider(ip, client)
		if err == nil && geoInfo != nil && geoInfo.CountryCode != "" {
			return geoInfo, nil
		}
		if err != nil {
			log.Printf("GeoIP provider #%d failed: %v", i+1, err)
		}
	}

	return nil, fmt.Errorf("all GeoIP providers failed for IP: %s", ip)
}

func countryCodeToFlag(countryCode string) string {
	if len(countryCode) != 2 {
		return "🌐"
	}
	countryCode = strings.ToUpper(countryCode)
	flag := ""
	for _, r := range countryCode {
		flag += string(rune(0x1F1E6 + (r - 'A')))
	}
	return flag
}

func (nt *NetworkTester) TestProxyConnection(proxyPort int) (bool, string, float64) {
	startTime := time.Now()

	waitDeadline := time.Now().Add(nt.timeout)
	for time.Now().Before(waitDeadline) {
		if nt.isProxyResponsive(proxyPort) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
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

	case ProtocolShadowsocksR:
		return nil, fmt.Errorf("shadowsocksr protocol is not supported by xray-core")

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

	case ProtocolTrojan:
		outbound["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  config.Server,
					"port":     config.Port,
					"password": config.Password,
					"level":    0,
				},
			},
		}

	case ProtocolHysteria, ProtocolHysteria2, ProtocolTUIC:
		return nil, fmt.Errorf("%s protocol is not supported by xray-core", config.Protocol)
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
	mu        sync.Mutex
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

func (pm *ProcessManager) HasProcess(pid int) bool {
	_, ok := pm.processes.Load(pid)
	return ok
}

func (pm *ProcessManager) KillProcess(pid int) error {
	value, ok := pm.processes.Load(pid)
	if !ok {
		return fmt.Errorf("process not found")
	}
	cmd, ok := value.(*exec.Cmd)
	if !ok || cmd == nil || cmd.Process == nil {
		pm.processes.Delete(pid)
		return fmt.Errorf("invalid process")
	}

	if err := cmd.Process.Kill(); err != nil {
		pm.processes.Delete(pid)
		return fmt.Errorf("failed to kill process %d: %w", pid, err)
	}

	pm.processes.Delete(pid)
	go func(c *exec.Cmd) {
		c.Wait()
	}(cmd)

	return nil
}

func (pm *ProcessManager) Cleanup() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var pids []int
	pm.processes.Range(func(key, value interface{}) bool {
		if pid, ok := key.(int); ok {
			pids = append(pids, pid)
		}
		return true
	})

	for _, pid := range pids {
		pm.KillProcess(pid)
	}

	time.Sleep(200 * time.Millisecond)
}

func (pm *ProcessManager) GetProcessCount() int {
	count := 0
	pm.processes.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func (pm *ProcessManager) ForceCleanupAll() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var cmdsToKill []*exec.Cmd

	pm.processes.Range(func(key, value interface{}) bool {
		if cmd, ok := value.(*exec.Cmd); ok {
			if cmd.Process != nil {
				cmdsToKill = append(cmdsToKill, cmd)
			}
		}
		pm.processes.Delete(key)
		return true
	})

	for _, cmd := range cmdsToKill {
		cmd.Process.Kill()
	}

	for _, cmd := range cmdsToKill {
		go func(c *exec.Cmd) {
			c.Wait()
		}(cmd)
	}

	return len(cmdsToKill)
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
	protocols := []ProxyProtocol{ProtocolShadowsocks, ProtocolShadowsocksR, ProtocolVMess, ProtocolVLESS, ProtocolTrojan, ProtocolHysteria, ProtocolHysteria2, ProtocolTUIC}
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
		ProtocolShadowsocks:  "shadowsocks",
		ProtocolShadowsocksR: "shadowsocksr",
		ProtocolVMess:        "vmess",
		ProtocolVLESS:        "vless",
		ProtocolTrojan:       "trojan",
		ProtocolHysteria:     "hysteria",
		ProtocolHysteria2:    "hysteria2",
		ProtocolTUIC:         "tuic",
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
	generalJSONFile.WriteString("# Protocols: Shadowsocks, ShadowsocksR, VMess, VLESS, Trojan, Hysteria, Hysteria2, TUIC\n\n")
	pt.generalJSONFile = generalJSONFile

	generalURLFile, err := os.Create(filepath.Join(pt.config.DataDir, "working_url", "working_all_urls.txt"))
	if err != nil {
		return err
	}
	generalURLFile.WriteString("# All Working Configurations (URL Format)\n")
	generalURLFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
	generalURLFile.WriteString("# Format: Each line contains one working configuration as URL\n")
	generalURLFile.WriteString("# Protocols: Shadowsocks, ShadowsocksR, VMess, VLESS, Trojan, Hysteria, Hysteria2, TUIC\n\n")
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

	seenHashes := make(map[string]bool)

	log.Printf("Loading %s configurations from: %s", protocol, filePath)

	switch protocol {
	case ProtocolShadowsocks:
		return pt.loadShadowsocksConfigsFromReader(file, seenHashes)
	case ProtocolShadowsocksR:
		return pt.loadShadowsocksRConfigs(file, seenHashes)
	case ProtocolVMess:
		return pt.loadVMessConfigsFromReader(file, seenHashes)
	case ProtocolVLESS:
		return pt.loadVLessConfigs(file, seenHashes)
	case ProtocolTrojan:
		return pt.loadTrojanConfigs(file, seenHashes)
	case ProtocolHysteria:
		return pt.loadHysteriaConfigs(file, seenHashes)
	case ProtocolHysteria2:
		return pt.loadHysteria2Configs(file, seenHashes)
	case ProtocolTUIC:
		return pt.loadTUICConfigs(file, seenHashes)
	}

	return nil, fmt.Errorf("unsupported protocol: %s", protocol)
}

func decodeJSONList[T any](r io.Reader) ([]T, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var arr []T
	if len(data) == 0 {
		return arr, nil
	}
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(line), &item); err == nil {
			arr = append(arr, item)
		} else {
			continue
		}
	}
	if err := scanner.Err(); err != nil {
		return arr, err
	}
	return arr, nil
}

func (pt *ProxyTester) loadShadowsocksConfigsFromReader(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type SSConfig struct {
		Server     string `json:"server"`
		ServerPort int    `json:"server_port"`
		Password   string `json:"password"`
		Method     string `json:"method"`
		Name       string `json:"name"`
	}

	var data []SSConfig
	if arr, err := decodeJSONList[SSConfig](file); err == nil {
		data = arr
	} else {
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

func (pt *ProxyTester) loadVMessConfigsFromReader(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
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
	if arr, err := decodeJSONList[VMConfig](file); err == nil {
		data = arr
	} else {
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
		if _, err2 := file.Seek(0, io.SeekStart); err2 == nil {
			if arr, err3 := decodeJSONList[VLConfig](file); err3 == nil {
				data = arr
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
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

func (pt *ProxyTester) loadShadowsocksRConfigs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type SSRConfig struct {
		Server        string `json:"server"`
		ServerPort    int    `json:"server_port"`
		Password      string `json:"password"`
		Method        string `json:"method"`
		Protocol      string `json:"protocol"`
		ProtocolParam string `json:"protocol_param"`
		Obfs          string `json:"obfs"`
		ObfsParam     string `json:"obfs_param"`
		Name          string `json:"name"`
	}

	var data []SSRConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		if _, err2 := file.Seek(0, io.SeekStart); err2 == nil {
			if arr, err3 := decodeJSONList[SSRConfig](file); err3 == nil {
				data = arr
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	var configs []ProxyConfig
	for _, configData := range data {
		config := ProxyConfig{
			Protocol:       ProtocolShadowsocksR,
			Server:         configData.Server,
			Port:           configData.ServerPort,
			Method:         configData.Method,
			Password:       configData.Password,
			Protocol_Param: configData.ProtocolParam,
			Obfs:           configData.Obfs,
			ObfsParam:      configData.ObfsParam,
			Remarks:        configData.Name,
			Network:        "tcp",
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

func (pt *ProxyTester) loadTrojanConfigs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type TrojanConfig struct {
		Address     string `json:"address"`
		Port        int    `json:"port"`
		Password    string `json:"password"`
		Name        string `json:"name"`
		Type        string `json:"type"`
		Host        string `json:"host"`
		Path        string `json:"path"`
		SNI         string `json:"sni"`
		ALPN        string `json:"alpn"`
		Fingerprint string `json:"fingerprint"`
	}

	var data []TrojanConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		if _, err2 := file.Seek(0, io.SeekStart); err2 == nil {
			if arr, err3 := decodeJSONList[TrojanConfig](file); err3 == nil {
				data = arr
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	var configs []ProxyConfig
	for _, configData := range data {
		config := ProxyConfig{
			Protocol:    ProtocolTrojan,
			Server:      configData.Address,
			Port:        configData.Port,
			Password:    configData.Password,
			Network:     configData.Type,
			Host:        configData.Host,
			Path:        configData.Path,
			SNI:         configData.SNI,
			ALPN:        configData.ALPN,
			Fingerprint: configData.Fingerprint,
			Remarks:     configData.Name,
			TLS:         "tls",
		}

		if config.Network == "" {
			config.Network = "tcp"
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

func (pt *ProxyTester) loadHysteriaConfigs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type HysteriaConfig struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Auth     string `json:"auth"`
		Protocol string `json:"protocol"`
		UpMbps   string `json:"upmbps"`
		DownMbps string `json:"downmbps"`
		Obfs     string `json:"obfs"`
		Peer     string `json:"peer"`
		ALPN     string `json:"alpn"`
		Insecure string `json:"insecure"`
		Name     string `json:"name"`
	}

	var data []HysteriaConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		if _, err2 := file.Seek(0, io.SeekStart); err2 == nil {
			if arr, err3 := decodeJSONList[HysteriaConfig](file); err3 == nil {
				data = arr
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	var configs []ProxyConfig
	for _, configData := range data {
		upMbps := 0
		if configData.UpMbps != "" {
			if val, err := strconv.Atoi(configData.UpMbps); err == nil {
				upMbps = val
			}
		}

		downMbps := 0
		if configData.DownMbps != "" {
			if val, err := strconv.Atoi(configData.DownMbps); err == nil {
				downMbps = val
			}
		}

		insecure := false
		if configData.Insecure == "1" || configData.Insecure == "true" {
			insecure = true
		}

		sni := configData.Peer
		if sni == "" {
			sni = configData.Address
		}

		config := ProxyConfig{
			Protocol: ProtocolHysteria,
			Server:   configData.Address,
			Port:     configData.Port,
			AuthStr:  configData.Auth,
			UpMbps:   upMbps,
			DownMbps: downMbps,
			Obfs:     configData.Obfs,
			SNI:      sni,
			ALPN:     configData.ALPN,
			Insecure: insecure,
			Remarks:  configData.Name,
			Network:  "udp",
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

func (pt *ProxyTester) loadHysteria2Configs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type Hysteria2Config struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Auth     string `json:"auth"`
		Obfs     string `json:"obfs"`
		SNI      string `json:"sni"`
		Insecure string `json:"insecure"`
		Name     string `json:"name"`
	}

	var data []Hysteria2Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		if _, err2 := file.Seek(0, io.SeekStart); err2 == nil {
			if arr, err3 := decodeJSONList[Hysteria2Config](file); err3 == nil {
				data = arr
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	var configs []ProxyConfig
	for _, configData := range data {
		insecure := false
		if configData.Insecure == "1" || configData.Insecure == "true" {
			insecure = true
		}

		config := ProxyConfig{
			Protocol: ProtocolHysteria2,
			Server:   configData.Address,
			Port:     configData.Port,
			Password: configData.Auth,
			Obfs:     configData.Obfs,
			SNI:      configData.SNI,
			Insecure: insecure,
			Remarks:  configData.Name,
			Network:  "udp",
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

func (pt *ProxyTester) loadTUICConfigs(file *os.File, seenHashes map[string]bool) ([]ProxyConfig, error) {
	type TUICConfig struct {
		Address          string `json:"address"`
		Port             int    `json:"port"`
		UUID             string `json:"uuid"`
		Password         string `json:"password"`
		CongestionControl string `json:"congestion_control"`
		ALPN             string `json:"alpn"`
		SNI              string `json:"sni"`
		AllowInsecure    string `json:"allow_insecure"`
		Name             string `json:"name"`
	}

	var data []TUICConfig
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		if _, err2 := file.Seek(0, io.SeekStart); err2 == nil {
			if arr, err3 := decodeJSONList[TUICConfig](file); err3 == nil {
				data = arr
			} else {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	var configs []ProxyConfig
	for _, configData := range data {
		insecure := false
		if configData.AllowInsecure == "1" || configData.AllowInsecure == "true" {
			insecure = true
		}

		config := ProxyConfig{
			Protocol:       ProtocolTUIC,
			Server:         configData.Address,
			Port:           configData.Port,
			UUID:           configData.UUID,
			Password:       configData.Password,
			CongestionCtrl: configData.CongestionControl,
			ALPN:           configData.ALPN,
			SNI:            configData.SNI,
			Insecure:       insecure,
			Remarks:        configData.Name,
			Network:        "udp",
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
	case ProtocolShadowsocksR:
		return config.Method != "" && config.Password != ""
	case ProtocolVMess:
		return pt.isValidUUID(config.UUID)
	case ProtocolVLESS:
		return pt.isValidUUID(config.UUID)
	case ProtocolTrojan:
		return config.Password != ""
	case ProtocolHysteria:
		return config.AuthStr != ""
	case ProtocolHysteria2:
		return config.Password != ""
	case ProtocolTUIC:
		return config.UUID != "" && config.Password != ""
	}

	return false
}

func (pt *ProxyTester) getConfigHash(config *ProxyConfig) string {
	var hashStr string
	switch config.Protocol {
	case ProtocolShadowsocks:
		hashStr = fmt.Sprintf("ss://%s:%d:%s:%s", config.Server, config.Port, config.Method, config.Password)
	case ProtocolShadowsocksR:
		hashStr = fmt.Sprintf("ssr://%s:%d:%s:%s:%s:%s", config.Server, config.Port, config.Method, config.Password, config.Protocol_Param, config.Obfs)
	case ProtocolVMess:
		hashStr = fmt.Sprintf("vmess://%s:%d:%s:%d:%s", config.Server, config.Port, config.UUID, config.AlterID, config.Network)
	case ProtocolVLESS:
		hashStr = fmt.Sprintf("vless://%s:%d:%s:%s", config.Server, config.Port, config.UUID, config.Network)
	case ProtocolTrojan:
		hashStr = fmt.Sprintf("trojan://%s:%d:%s:%s", config.Server, config.Port, config.Password, config.Network)
	case ProtocolHysteria:
		hashStr = fmt.Sprintf("hysteria://%s:%d:%s", config.Server, config.Port, config.AuthStr)
	case ProtocolHysteria2:
		hashStr = fmt.Sprintf("hysteria2://%s:%d:%s", config.Server, config.Port, config.Password)
	case ProtocolTUIC:
		hashStr = fmt.Sprintf("tuic://%s:%d:%s:%s", config.Server, config.Port, config.UUID, config.Password)
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

	if process.Process != nil {
		pt.processManager.RegisterProcess(process.Process.Pid, process)
	}

	readyBy := time.Now().Add(3 * time.Second)
	for !pt.networkTester.isProxyResponsive(proxyPort) && time.Now().Before(readyBy) {
		time.Sleep(100 * time.Millisecond)
	}

	if process.ProcessState != nil && process.ProcessState.Exited() {
		result.Result = ResultConnectionError
		result.ErrorMessage = "Xray process terminated"
		if process.Process != nil {
			pt.processManager.KillProcess(process.Process.Pid)
		}
		return result
	}

	success, externalIP, responseTime := pt.networkTester.TestProxyConnection(proxyPort)
	if success {
		result.Result = ResultSuccess
		result.ExternalIP = externalIP
		result.ResponseTime = &responseTime

		if externalIP != "" {
			geoInfo, err := pt.networkTester.GetCountryInfo(externalIP)
			if err == nil {
				result.CountryCode = geoInfo.CountryCode
				result.CountryName = geoInfo.CountryName
				result.CountryFlag = geoInfo.CountryFlag
				log.Printf("Country detected: %s %s", geoInfo.CountryFlag, geoInfo.CountryName)
			} else {
				log.Printf("GeoIP lookup failed: %v", err)
			}
		}

		if pt.config.IncrementalSave {
			pt.saveConfigImmediately(result)
		}

		log.Printf("SUCCESS: %s://%s:%d (%.3fs)", config.Protocol, config.Server, config.Port, responseTime)
	} else {
		result.Result = ResultNetworkError
		result.ErrorMessage = "Network test failed"
	}

	if process != nil && process.Process != nil {
		_ = pt.processManager.KillProcess(process.Process.Pid)
		waitDeadline := time.Now().Add(2 * time.Second)
		for pt.processManager.HasProcess(process.Process.Pid) && time.Now().Before(waitDeadline) {
			time.Sleep(50 * time.Millisecond)
		}
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
		return fmt.Errorf("syntax test failed: %s", strings.TrimSpace(string(output)))
	}

	return nil
}

func (pt *ProxyTester) startXrayProcess(configFile string) (*exec.Cmd, error) {
	cmd := exec.Command(pt.configGenerator.xrayPath, "run", "-config", configFile)

	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if runtime.GOOS != "windows" {
	}

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
		if result.CountryFlag != "" && result.CountryName != "" {
			fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s | Country: %s %s\n",
				timestamp, *result.ResponseTime, result.ExternalIP, result.CountryFlag, result.CountryName)
		} else {
			fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s\n",
				timestamp, *result.ResponseTime, result.ExternalIP)
		}
		fmt.Fprintf(file, "%s\n\n", configLine)
		file.Sync()
	}

	if file, ok := pt.urlFiles[protocol]; ok {
		configURL := pt.createConfigURL(result)
		if result.CountryFlag != "" && result.CountryName != "" {
			fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s | Country: %s %s\n",
				timestamp, *result.ResponseTime, result.ExternalIP, result.CountryFlag, result.CountryName)
		} else {
			fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s\n",
				timestamp, *result.ResponseTime, result.ExternalIP)
		}
		fmt.Fprintf(file, "%s\n\n", configURL)
		file.Sync()
	}

	if pt.generalJSONFile != nil {
		configLine := pt.createWorkingConfigLine(result)
		if result.CountryFlag != "" && result.CountryName != "" {
			fmt.Fprintf(pt.generalJSONFile, "# [%s] Tested at: %s | Response: %.3fs | IP: %s | Country: %s %s\n",
				strings.ToUpper(string(protocol)), timestamp, *result.ResponseTime, result.ExternalIP, result.CountryFlag, result.CountryName)
		} else {
			fmt.Fprintf(pt.generalJSONFile, "# [%s] Tested at: %s | Response: %.3fs | IP: %s\n",
				strings.ToUpper(string(protocol)), timestamp, *result.ResponseTime, result.ExternalIP)
		}
		fmt.Fprintf(pt.generalJSONFile, "%s\n\n", configLine)
		pt.generalJSONFile.Sync()
	}

	if pt.generalURLFile != nil {
		configURL := pt.createConfigURL(result)
		if result.CountryFlag != "" && result.CountryName != "" {
			fmt.Fprintf(pt.generalURLFile, "# [%s] Tested at: %s | Response: %.3fs | IP: %s | Country: %s %s\n",
				strings.ToUpper(string(protocol)), timestamp, *result.ResponseTime, result.ExternalIP, result.CountryFlag, result.CountryName)
		} else {
			fmt.Fprintf(pt.generalURLFile, "# [%s] Tested at: %s | Response: %.3fs | IP: %s\n",
				strings.ToUpper(string(protocol)), timestamp, *result.ResponseTime, result.ExternalIP)
		}
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
	case ProtocolShadowsocksR:
		data["method"] = config.Method
		data["password"] = config.Password
		data["protocol"] = config.Protocol_Param
		data["obfs"] = config.Obfs
		data["obfs_param"] = config.ObfsParam
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
	case ProtocolTrojan:
		data["password"] = config.Password
		data["path"] = config.Path
		data["host"] = config.Host
		data["sni"] = config.SNI
		data["alpn"] = config.ALPN
		data["fingerprint"] = config.Fingerprint
	case ProtocolHysteria:
		data["auth_str"] = config.AuthStr
		data["up_mbps"] = config.UpMbps
		data["down_mbps"] = config.DownMbps
		data["obfs"] = config.Obfs
		data["sni"] = config.SNI
		data["alpn"] = config.ALPN
		data["insecure"] = config.Insecure
	case ProtocolHysteria2:
		data["password"] = config.Password
		data["obfs"] = config.Obfs
		data["sni"] = config.SNI
		data["insecure"] = config.Insecure
	case ProtocolTUIC:
		data["uuid"] = config.UUID
		data["password"] = config.Password
		data["congestion_control"] = config.CongestionCtrl
		data["alpn"] = config.ALPN
		data["sni"] = config.SNI
		data["insecure"] = config.Insecure
	}

	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func (pt *ProxyTester) createConfigURL(result *TestResultData) string {
	config := &result.Config
	remarks := result.CountryFlag

	switch config.Protocol {
	case ProtocolShadowsocks:
		auth := fmt.Sprintf("%s:%s", config.Method, config.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(auth))
		return fmt.Sprintf("ss://%s@%s:%d#%s", authB64, config.Server, config.Port, url.QueryEscape(remarks))

	case ProtocolShadowsocksR:
		ssrStr := fmt.Sprintf("%s:%d:%s:%s:%s:%s", config.Server, config.Port, config.Protocol_Param, config.Method, config.Obfs, base64.URLEncoding.EncodeToString([]byte(config.Password)))
		queryParams := []string{}
		if config.ObfsParam != "" {
			queryParams = append(queryParams, "obfsparam="+base64.URLEncoding.EncodeToString([]byte(config.ObfsParam)))
		}
		if config.Protocol_Param != "" {
			queryParams = append(queryParams, "protoparam="+base64.URLEncoding.EncodeToString([]byte(config.Protocol_Param)))
		}
		queryParams = append(queryParams, "remarks="+base64.URLEncoding.EncodeToString([]byte(remarks)))
		if len(queryParams) > 0 {
			ssrStr += "/?" + strings.Join(queryParams, "&")
		}
		return fmt.Sprintf("ssr://%s", base64.URLEncoding.EncodeToString([]byte(ssrStr)))

	case ProtocolVMess:
		vmessConfig := map[string]interface{}{
			"v":    "2",
			"ps":   remarks,
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
		return fmt.Sprintf("vless://%s@%s:%d%s#%s", config.UUID, config.Server, config.Port, query, url.QueryEscape(remarks))

	case ProtocolTrojan:
		params := url.Values{}
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
		if config.Fingerprint != "" {
			params.Add("fp", config.Fingerprint)
		}
		query := ""
		if len(params) > 0 {
			query = "?" + params.Encode()
		}
		return fmt.Sprintf("trojan://%s@%s:%d%s#%s", config.Password, config.Server, config.Port, query, url.QueryEscape(remarks))

	case ProtocolHysteria:
		params := url.Values{}
		if config.UpMbps > 0 {
			params.Add("upmbps", strconv.Itoa(config.UpMbps))
		}
		if config.DownMbps > 0 {
			params.Add("downmbps", strconv.Itoa(config.DownMbps))
		}
		if config.Obfs != "" {
			params.Add("obfs", config.Obfs)
		}
		if config.SNI != "" {
			params.Add("peer", config.SNI)
		}
		if config.ALPN != "" {
			params.Add("alpn", config.ALPN)
		}
		if config.Insecure {
			params.Add("insecure", "1")
		}
		query := ""
		if len(params) > 0 {
			query = "?" + params.Encode()
		}
		return fmt.Sprintf("hysteria://%s@%s:%d%s#%s", config.AuthStr, config.Server, config.Port, query, url.QueryEscape(remarks))

	case ProtocolHysteria2:
		params := url.Values{}
		if config.Obfs != "" {
			params.Add("obfs", config.Obfs)
		}
		if config.SNI != "" {
			params.Add("sni", config.SNI)
		}
		if config.Insecure {
			params.Add("insecure", "1")
		}
		query := ""
		if len(params) > 0 {
			query = "?" + params.Encode()
		}
		return fmt.Sprintf("hysteria2://%s@%s:%d%s#%s", config.Password, config.Server, config.Port, query, url.QueryEscape(remarks))

	case ProtocolTUIC:
		params := url.Values{}
		if config.CongestionCtrl != "" {
			params.Add("congestion_control", config.CongestionCtrl)
		}
		if config.ALPN != "" {
			params.Add("alpn", config.ALPN)
		}
		if config.SNI != "" {
			params.Add("sni", config.SNI)
		}
		if config.Insecure {
			params.Add("allow_insecure", "1")
		}
		query := ""
		if len(params) > 0 {
			query = "?" + params.Encode()
		}
		return fmt.Sprintf("tuic://%s:%s@%s:%d%s#%s", config.UUID, config.Password, config.Server, config.Port, query, url.QueryEscape(remarks))
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

		pt.reportSystemStatus(batchID)

		if end < totalConfigs {
			pt.cleanupBetweenBatches()

			log.Printf("⏸️  Resting for 10 seconds before next batch...")
			time.Sleep(10 * time.Second)
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

func (pt *ProxyTester) getSystemMemoryUsage() (used uint64, total uint64, err error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	if runtime.GOOS == "windows" {
		cmdUsed := exec.Command("powershell", "-Command", "(Get-Process | Measure-Object WorkingSet64 -Sum).Sum / 1MB")
		outputUsed, errUsed := cmdUsed.Output()

		cmdTotal := exec.Command("powershell", "-Command", "(Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize / 1KB")
		outputTotal, errTotal := cmdTotal.Output()

		if errUsed == nil && errTotal == nil {
			if memUsedMB, err := strconv.ParseFloat(strings.TrimSpace(string(outputUsed)), 64); err == nil {
				if memTotalMB, err := strconv.ParseFloat(strings.TrimSpace(string(outputTotal)), 64); err == nil {
					return uint64(memUsedMB), uint64(memTotalMB), nil
				}
			}
		}
	} else {
		cmd := exec.Command("sh", "-c", "free -m | awk '/^Mem:/ {print $3, $2}'")
		output, cmdErr := cmd.Output()
		if cmdErr == nil {
			parts := strings.Fields(strings.TrimSpace(string(output)))
			if len(parts) >= 2 {
				if memUsedMB, err := strconv.ParseUint(parts[0], 10, 64); err == nil {
					if memTotalMB, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
						return memUsedMB, memTotalMB, nil
					}
				}
			}
		}
	}

	return m.Alloc / 1024 / 1024, 0, nil
}

func (pt *ProxyTester) countXrayCoreProcesses() int {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-Command", "(Get-Process -Name '*xray*' -ErrorAction SilentlyContinue | Measure-Object).Count")
	} else {
		cmd = exec.Command("sh", "-c", "ps aux | grep -i xray | grep -v grep | wc -l")
	}

	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	count, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil {
		return 0
	}

	return count
}

func (pt *ProxyTester) cleanupBetweenBatches() {
	log.Println(strings.Repeat("-", 70))
	log.Println(" Cleaning up resources before next batch...")

	trackedProcessesBefore := pt.processManager.GetProcessCount()
	systemProcessesBefore := pt.countXrayCoreProcesses()
	log.Printf("   Tracked processes: %d", trackedProcessesBefore)
	log.Printf("   System xray-core processes: %d", systemProcessesBefore)

	log.Println("   Force killing all tracked xray processes...")
	killedCount := pt.processManager.ForceCleanupAll()

	log.Println("  ⏳ Waiting for processes to terminate...")
	time.Sleep(2 * time.Second)

	trackedProcessesAfter := pt.processManager.GetProcessCount()
	systemProcessesAfter := pt.countXrayCoreProcesses()

	log.Printf("   Tracked processes killed: %d", killedCount)
	log.Printf("   Tracked processes remaining: %d", trackedProcessesAfter)

	if systemProcessesAfter == 0 {
		log.Printf("   System xray-core processes cleaned: %d", systemProcessesBefore)
	} else {
		log.Printf("    System xray-core processes still running: %d", systemProcessesAfter)
	}

	log.Println("   Releasing all used ports...")
	portsBefore := 0
	pt.portManager.usedPorts.Range(func(key, value interface{}) bool {
		portsBefore++
		return true
	})
	log.Printf("   Used ports before cleanup: %d", portsBefore)

	pt.portManager.cleanup()

	portsAfter := 0
	pt.portManager.usedPorts.Range(func(key, value interface{}) bool {
		portsAfter++
		return true
	})
	log.Printf("   Used ports released: %d", portsBefore-portsAfter)
	log.Printf("   Used ports remaining: %d", portsAfter)

	runtime.GC()
	log.Println("    Garbage collection completed")

	log.Println("   Cleanup completed successfully!")
	log.Println(strings.Repeat("-", 70))
}

func (pt *ProxyTester) reportSystemStatus(batchID int) {
	log.Println(strings.Repeat("=", 70))
	log.Printf(" System Status After Batch %d:", batchID)
	log.Println(strings.Repeat("=", 70))

	memUsed, memTotal, err := pt.getSystemMemoryUsage()
	if err == nil {
		if memTotal > 0 {
			usagePercent := float64(memUsed) / float64(memTotal) * 100
			log.Printf(" RAM Usage: %.2f MB / %.2f MB (%.1f%%)",
				float64(memUsed), float64(memTotal), usagePercent)
		} else {
			log.Printf(" RAM Usage: %.2f MB", float64(memUsed))
		}
	} else {
		log.Printf(" RAM Usage: Unable to retrieve (Error: %v)", err)
	}

	processCount := pt.countXrayCoreProcesses()
	log.Printf("🔧 Xray-core Processes: %d", processCount)

	log.Println(strings.Repeat("=", 70))
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
	protocols := []ProxyProtocol{ProtocolShadowsocks, ProtocolShadowsocksR, ProtocolVMess, ProtocolVLESS, ProtocolTrojan, ProtocolHysteria, ProtocolHysteria2, ProtocolTUIC}
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

func init() {
	rand.Seed(time.Now().UnixNano())
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

	configFilesOrdered := []struct {
		protocol ProxyProtocol
		filePath string
	}{
		{ProtocolShadowsocks, filepath.Join(config.DataDir, "deduplicated_urls", "ss.json")},
		{ProtocolShadowsocksR, filepath.Join(config.DataDir, "deduplicated_urls", "ssr.json")},
		{ProtocolVMess, filepath.Join(config.DataDir, "deduplicated_urls", "vmess.json")},
		{ProtocolVLESS, filepath.Join(config.DataDir, "deduplicated_urls", "vless.json")},
		{ProtocolTrojan, filepath.Join(config.DataDir, "deduplicated_urls", "trojan.json")},
		{ProtocolHysteria, filepath.Join(config.DataDir, "deduplicated_urls", "hy.json")},
		{ProtocolHysteria2, filepath.Join(config.DataDir, "deduplicated_urls", "hysteria2.json")},
		{ProtocolTUIC, filepath.Join(config.DataDir, "deduplicated_urls", "tuic.json")},
	}

	var allResults []*TestResultData
	totalWorkingConfigs := 0

	for _, configFile := range configFilesOrdered {
		protocol := configFile.protocol
		filePath := configFile.filePath

		log.Println(strings.Repeat("=", 70))
		log.Printf(" Starting tests for %s protocol", strings.ToUpper(string(protocol)))
		log.Println(strings.Repeat("=", 70))

		if _, err := os.Stat(filePath); err == nil {
			configs, err := tester.LoadConfigsFromJSON(filePath, protocol)
			if err != nil {
				log.Printf("Failed to load %s configs: %v", protocol, err)
				continue
			}

			if len(configs) == 0 {
				log.Printf("No valid %s configurations found", protocol)
				continue
			}

			log.Printf("Testing %d %s configurations...", len(configs), protocol)

			results := tester.RunTests(configs)
			allResults = append(allResults, results...)

			workingCount := 0
			for _, result := range results {
				if result.Result == ResultSuccess {
					workingCount++
				}
			}
			totalWorkingConfigs += workingCount

			log.Printf(" %s testing completed: %d working configurations found", strings.ToUpper(string(protocol)), workingCount)
		} else {
			log.Printf("Config file not found: %s", filePath)
		}
	}

	if totalWorkingConfigs > 0 {
		log.Println(strings.Repeat("=", 70))
		log.Printf("\n FINAL RESULTS ")
		log.Printf("Total working configurations: %d", totalWorkingConfigs)
		log.Printf("\nWorking configurations saved to:")
		log.Printf("  JSON: %s/working_json/working_*.txt", config.DataDir)
		log.Printf("  URL: %s/working_url/working_*_urls.txt", config.DataDir)
		log.Printf("  All configs (JSON): %s/working_json/working_all_configs.txt", config.DataDir)
		log.Printf("  All configs (URL): %s/working_url/working_all_urls.txt", config.DataDir)
		log.Println(strings.Repeat("=", 70))
	} else {
		log.Println("No working configurations found")
	}
}
