// proxy-tester.go  (rev-250920-fixed)
// Complete, self-contained, ready to build
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

/* ==========================  TYPES  ========================== */

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
		MaxWorkers:      getEnvIntOrDefault("PROXY_MAX_WORKERS", 100),
		Timeout:         time.Duration(getEnvIntOrDefault("PROXY_TIMEOUT", 5)) * time.Second,
		BatchSize:       getEnvIntOrDefault("PROXY_BATCH_SIZE", 100),
		IncrementalSave: getEnvBoolOrDefault("PROXY_INCREMENTAL_SAVE", true),
		DataDir:         dataDir,
		ConfigDir:       configDir,
		LogDir:          logDir,
		StartPort:       getEnvIntOrDefault("PROXY_START_PORT", 10000),
		EndPort:         getEnvIntOrDefault("PROXY_END_PORT", 20000),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, dv int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return dv
}

func getEnvBoolOrDefault(key string, dv bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return dv
}

/* ==========================  PROXY CONFIG  ========================== */

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

/* ==========================  TEST RESULT  ========================== */

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

/* ==========================  PORT MANAGER  ========================== */

type PortManager struct {
	startPort      int
	endPort        int
	availablePorts chan int
	usedPorts      sync.Map
	mu             sync.Mutex
	initialized    int32
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
	// kernel TIME_WAIT grace
	time.Sleep(100 * time.Millisecond)
	go func() {
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

/* ==========================  NETWORK TESTER  ========================== */

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
	start := time.Now()
	if !nt.isProxyResponsive(proxyPort) {
		return false, "", time.Since(start).Seconds()
	}
	testCount := 4
	if len(nt.testURLs) < testCount {
		testCount = len(nt.testURLs)
	}
	shuffled := make([]string, len(nt.testURLs))
	copy(shuffled, nt.testURLs)
	rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	for i := 0; i < testCount; i++ {
		ok, ip, rt := nt.singleTest(proxyPort, shuffled[i])
		if ok {
			return true, ip, rt
		}
	}
	return false, "", time.Since(start).Seconds()
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
	start := time.Now()
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return false, "", time.Since(start).Seconds()
	}
	tr := &http.Transport{
		Dial:                dialer.Dial,
		DisableKeepAlives:   true,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 0,
		IdleConnTimeout:     1 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: nt.timeout}
	resp, err := client.Get(testURL)
	if err != nil {
		return false, "", time.Since(start).Seconds()
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, "", time.Since(start).Seconds()
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", time.Since(start).Seconds()
	}
	rt := time.Since(start).Seconds()
	ipText := strings.TrimSpace(string(body))
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "json") {
		var d map[string]interface{}
		if json.Unmarshal(body, &d) == nil {
			if orig, ok := d["origin"].(string); ok {
				ipText = orig
			} else if ip, ok := d["ip"].(string); ok {
				ipText = ip
			}
		}
	}
	if net.ParseIP(ipText) != nil {
		return true, ipText, rt
	}
	return false, "", rt
}

/* ==========================  XRAY CONFIG GENERATOR  ========================== */

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
	cands := []string{"xray", "./xray", "/usr/local/bin/xray", "/usr/bin/xray"}
	for _, c := range cands {
		if _, err := exec.LookPath(c); err == nil {
			return c
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "xray"
}

func (xcg *XrayConfigGenerator) ValidateXray() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, xcg.xrayPath, "version")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("xray validation failed: %w", err)
	}
	log.Printf("Xray version: %s", strings.TrimSpace(string(out)))
	return nil
}

func (xcg *XrayConfigGenerator) GenerateConfig(cfg *ProxyConfig, listenPort int) (map[string]interface{}, error) {
	out := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "error"},
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
				"sniffing": map[string]interface{}{"enabled": false},
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol":       string(cfg.Protocol),
				"settings":       map[string]interface{}{},
				"streamSettings": map[string]interface{}{},
			},
		},
	}
	ob := out["outbounds"].([]map[string]interface{})[0]
	switch cfg.Protocol {
	case ProtocolShadowsocks:
		ob["settings"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{"address": cfg.Server, "port": cfg.Port, "method": cfg.Method, "password": cfg.Password, "level": 0},
			},
		}
	case ProtocolVMess:
		ob["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": cfg.Server,
					"port":    cfg.Port,
					"users": []map[string]interface{}{
						{"id": cfg.UUID, "alterId": cfg.AlterID, "security": cfg.Cipher, "level": 0},
					},
				},
			},
		}
	case ProtocolVLESS:
		ob["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": cfg.Server,
					"port":    cfg.Port,
					"users": []map[string]interface{}{
						{"id": cfg.UUID, "flow": cfg.Flow, "encryption": cfg.Encrypt, "level": 0},
					},
				},
			},
		}
	}
	ss := ob["streamSettings"].(map[string]interface{})
	if cfg.Network != "" && cfg.Network != "tcp" {
		ss["network"] = cfg.Network
		switch cfg.Network {
		case "ws":
			ws := map[string]interface{}{}
			if cfg.Path != "" {
				ws["path"] = cfg.Path
			}
			if cfg.Host != "" {
				ws["headers"] = map[string]interface{}{"Host": cfg.Host}
			}
			ss["wsSettings"] = ws
		case "h2":
			h2 := map[string]interface{}{}
			if cfg.Path != "" {
				h2["path"] = cfg.Path
			}
			if cfg.Host != "" {
				h2["host"] = []string{cfg.Host}
			}
			ss["httpSettings"] = h2
		case "grpc":
			gs := map[string]interface{}{}
			if cfg.ServiceName != "" {
				gs["serviceName"] = cfg.ServiceName
			}
			ss["grpcSettings"] = gs
		}
	}
	if cfg.TLS != "" {
		ss["security"] = cfg.TLS
		tlsSets := map[string]interface{}{
			"allowInsecure": true,
		}
		if cfg.SNI != "" {
			tlsSets["serverName"] = cfg.SNI
		} else if cfg.Host != "" {
			tlsSets["serverName"] = cfg.Host
		}
		if cfg.ALPN != "" {
			tlsSets["alpn"] = strings.Split(cfg.ALPN, ",")
		}
		if cfg.Fingerprint != "" {
			tlsSets["fingerprint"] = cfg.Fingerprint
		}
		if cfg.TLS == "tls" {
			ss["tlsSettings"] = tlsSets
		} else if cfg.TLS == "reality" {
			ss["realitySettings"] = tlsSets
		}
	}
	return out, nil
}

/* ==========================  PROCESS MANAGER  ========================== */

type ProcessManager struct {
	processes sync.Map
	cleanup   int32
}

func NewProcessManager() *ProcessManager { return &ProcessManager{} }

func (pm *ProcessManager) RegisterProcess(pid int, cmd *exec.Cmd) { pm.processes.Store(pid, cmd) }

func (pm *ProcessManager) UnregisterProcess(pid int) { pm.processes.Delete(pid) }

func (pm *ProcessManager) KillProcess(pid int) error {
	if atomic.LoadInt32(&pm.cleanup) == 1 {
		return nil
	}
	if v, ok := pm.processes.Load(pid); ok {
		if cmd, ok := v.(*exec.Cmd); ok && cmd.Process != nil {
			// kill whole group
			_ = syscall.Kill(-pid, syscall.SIGTERM)
			time.Sleep(200 * time.Millisecond)
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			pm.UnregisterProcess(pid)
		}
	}
	return nil
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

/* ==========================  PROXY TESTER  ========================== */

type ProxyTester struct {
	config          *Config
	portManager     *PortManager
	processManager  *ProcessManager
	networkTester   *NetworkTester
	configGenerator *XrayConfigGenerator

	outputFiles     map[ProxyProtocol]*os.File
	urlFiles        map[ProxyProtocol]*os.File
	generalJSONFile *os.File
	generalURLFile  *os.File

	stats     sync.Map
	resultsMu sync.Mutex
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
	for _, p := range protocols {
		pt.stats.Store(p, map[string]*int64{"total": new(int64), "success": new(int64), "failed": new(int64)})
	}
	pt.stats.Store("overall", map[string]*int64{
		"total": new(int64), "success": new(int64), "failed": new(int64),
		"parse_errors": new(int64), "syntax_errors": new(int64), "connection_errors": new(int64),
		"timeouts": new(int64), "network_errors": new(int64),
	})
}

func (pt *ProxyTester) setupIncrementalSave() error {
	for _, dir := range []string{
		filepath.Join(pt.config.DataDir, "working_json"),
		filepath.Join(pt.config.DataDir, "working_url"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	protocols := map[ProxyProtocol]string{ProtocolShadowsocks: "shadowsocks", ProtocolVMess: "vmess", ProtocolVLESS: "vless"}
	ts := time.Now().Format("2006-01-02 15:04:05")
	for proto, name := range protocols {
		f1, err := os.Create(filepath.Join(pt.config.DataDir, "working_json", fmt.Sprintf("working_%s.txt", name)))
		if err != nil {
			return err
		}
		f1.WriteString(fmt.Sprintf("# %s (JSON)  –  %s\n\n", strings.ToUpper(name), ts))
		pt.outputFiles[proto] = f1

		f2, err := os.Create(filepath.Join(pt.config.DataDir, "working_url", fmt.Sprintf("working_%s_urls.txt", name)))
		if err != nil {
			return err
		}
		f2.WriteString(fmt.Sprintf("# %s (URL)  –  %s\n\n", strings.ToUpper(name), ts))
		pt.urlFiles[proto] = f2
	}
	f3, err := os.Create(filepath.Join(pt.config.DataDir, "working_json", "working_all_configs.txt"))
	if err != nil {
		return err
	}
	f3.WriteString("# All Working Configs (JSON)\n\n")
	pt.generalJSONFile = f3

	f4, err := os.Create(filepath.Join(pt.config.DataDir, "working_url", "working_all_urls.txt"))
	if err != nil {
		return err
	}
	f4.WriteString("# All Working Configs (URL)\n\n")
	pt.generalURLFile = f4
	return nil
}

/* --------------------  LOAD CONFIGS  -------------------- */

func (pt *ProxyTester) LoadConfigsFromJSON(filePath string, protocol ProxyProtocol) ([]ProxyConfig, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var configs []ProxyConfig
	seen := make(map[string]bool)
	log.Printf("Loading %s configurations from: %s", protocol, filePath)
	switch protocol {
	case ProtocolShadowsocks:
		configs, err = pt.loadShadowsocksConfigs(f, seen)
	case ProtocolVMess:
		configs, err = pt.loadVMessConfigs(f, seen)
	case ProtocolVLESS:
		configs, err = pt.loadVLessConfigs(f, seen)
	}
	if err != nil {
		return nil, err
	}
	log.Printf("Loaded %d unique %s configurations", len(configs), protocol)
	return configs, nil
}

type ssJSON struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Name       string `json:"name"`
}

func (pt *ProxyTester) loadShadowsocksConfigs(f *os.File, seen map[string]bool) ([]ProxyConfig, error) {
	var data []ssJSON
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	var out []ProxyConfig
	for _, v := range data {
		c := ProxyConfig{
			Protocol: ProtocolShadowsocks, Server: v.Server, Port: v.ServerPort,
			Method: v.Method, Password: v.Password, Remarks: v.Name, Network: "tcp",
		}
		if pt.isValidConfig(&c) {
			h := pt.getConfigHash(&c)
			if !seen[h] {
				seen[h] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

type vmJSON struct {
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

func (pt *ProxyTester) loadVMessConfigs(f *os.File, seen map[string]bool) ([]ProxyConfig, error) {
	var data []vmJSON
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	var out []ProxyConfig
	for _, v := range data {
		aid := 0
		if v.AlterId != "" {
			aid, _ = strconv.Atoi(v.AlterId)
		}
		c := ProxyConfig{
			Protocol: ProtocolVMess, Server: v.Address, Port: v.Port, UUID: v.ID,
			AlterID: aid, Cipher: v.Security, Network: v.Network, TLS: v.TLS,
			SNI: v.SNI, Path: v.Path, Host: v.Host, Remarks: v.Name, HeaderType: v.Type,
		}
		if pt.isValidConfig(&c) {
			h := pt.getConfigHash(&c)
			if !seen[h] {
				seen[h] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

type vlJSON struct {
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

func (pt *ProxyTester) loadVLessConfigs(f *os.File, seen map[string]bool) ([]ProxyConfig, error) {
	var data []vlJSON
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	var out []ProxyConfig
	for _, v := range data {
		c := ProxyConfig{
			Protocol: ProtocolVLESS, Server: v.Address, Port: v.Port, UUID: v.ID,
			Network: v.Type, TLS: v.TLS, SNI: v.SNI, Path: v.Path, Host: v.Host,
			Remarks: v.Name, Encrypt: "none",
		}
		if pt.isValidConfig(&c) {
			h := pt.getConfigHash(&c)
			if !seen[h] {
				seen[h] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

func (pt *ProxyTester) isValidUUID(uuid string) bool {
	re := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return re.MatchString(uuid)
}

func (pt *ProxyTester) isValidConfig(c *ProxyConfig) bool {
	if c.Server == "" || c.Port <= 0 || c.Port > 65535 {
		return false
	}
	switch c.Protocol {
	case ProtocolShadowsocks:
		return c.Method != "" && c.Password != ""
	case ProtocolVMess, ProtocolVLESS:
		return pt.isValidUUID(c.UUID)
	}
	return false
}

func (pt *ProxyTester) getConfigHash(c *ProxyConfig) string {
	var s string
	switch c.Protocol {
	case ProtocolShadowsocks:
		s = fmt.Sprintf("ss://%s:%d:%s:%s", c.Server, c.Port, c.Method, c.Password)
	case ProtocolVMess:
		s = fmt.Sprintf("vmess://%s:%d:%s:%d:%s", c.Server, c.Port, c.UUID, c.AlterID, c.Network)
	case ProtocolVLESS:
		s = fmt.Sprintf("vless://%s:%d:%s:%s", c.Server, c.Port, c.UUID, c.Network)
	}
	h := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}

/* --------------------  TEST SINGLE CONFIG  -------------------- */

func (pt *ProxyTester) TestSingleConfig(cfg *ProxyConfig, batchID int) *TestResultData {
	start := time.Now()
	var proxyPort int
	var proc *exec.Cmd
	var configFile string

	res := &TestResultData{Config: *cfg, BatchID: &batchID}

	defer func() {
		res.TestTime = time.Since(start).Seconds()
		if proc != nil && proc.Process != nil {
			pt.processManager.KillProcess(proc.Process.Pid)
		}
		if configFile != "" {
			os.Remove(configFile)
		}
		if proxyPort > 0 {
			pt.portManager.ReleasePort(proxyPort)
		}
	}()

	// port
	var ok bool
	proxyPort, ok = pt.portManager.GetAvailablePort()
	if !ok || proxyPort == 0 {
		res.Result = ResultPortConflict
		return res
	}
	res.ProxyPort = &proxyPort

	// generate xray json
	xrayConf, err := pt.configGenerator.GenerateConfig(cfg, proxyPort)
	if err != nil {
		res.Result = ResultInvalidConfig
		res.ErrorMessage = err.Error()
		return res
	}
	configFile, err = pt.writeConfigToTempFile(xrayConf)
	if err != nil {
		res.Result = ResultInvalidConfig
		res.ErrorMessage = err.Error()
		return res
	}

	// syntax test
	if err := pt.testConfigSyntax(configFile); err != nil {
		res.Result = ResultSyntaxError
		res.ErrorMessage = err.Error()
		return res
	}

	// start xray
	proc, err = pt.startXrayProcess(configFile)
	if err != nil {
		res.Result = ResultConnectionError
		res.ErrorMessage = err.Error()
		return res
	}
	pt.processManager.RegisterProcess(proc.Process.Pid, proc)

	// wait until socks up
	time.Sleep(time.Second)
	if proc.ProcessState != nil && proc.ProcessState.Exited() {
		res.Result = ResultConnectionError
		res.ErrorMessage = "xray exited early"
		return res
	}

	// test proxy
	ok, ip, rt := pt.networkTester.TestProxyConnection(proxyPort)
	if ok {
		res.Result = ResultSuccess
		res.ExternalIP = ip
		res.ResponseTime = &rt
		if pt.config.IncrementalSave {
			pt.saveConfigImmediately(res)
		}
		log.Printf("SUCCESS: %s://%s:%d (%.3fs)", cfg.Protocol, cfg.Server, cfg.Port, rt)
	} else {
		res.Result = ResultNetworkError
		res.ErrorMessage = "network test failed"
	}
	return res
}

func (pt *ProxyTester) writeConfigToTempFile(cfg map[string]interface{}) (string, error) {
	tmp, err := os.CreateTemp("", "xray-config-*.json")
	if err != nil {
		return "", err
	}
	defer tmp.Close()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func (pt *ProxyTester) testConfigSyntax(configFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, pt.configGenerator.xrayPath, "run", "-test", "-config", configFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("syntax test failed: %s", string(out))
	}
	return nil
}

func (pt *ProxyTester) startXrayProcess(configFile string) (*exec.Cmd, error) {
	cmd := exec.Command(pt.configGenerator.xrayPath, "run", "-config", configFile)
	// ⚠️ critical: create new process group
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

/* --------------------  BATCH TEST  -------------------- */

func (pt *ProxyTester) TestConfigs(configs []ProxyConfig, batchID int) []*TestResultData {
	if len(configs) == 0 {
		return nil
	}
	log.Printf("Testing batch %d with %d configurations...", batchID, len(configs))
	maxWorkers := pt.config.MaxWorkers
	if len(configs) < maxWorkers {
		maxWorkers = len(configs)
	}
	cfgChan := make(chan ProxyConfig, len(configs))
	resChan := make(chan *TestResultData, len(configs))
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cfg := range cfgChan {
				res := pt.TestSingleConfig(&cfg, batchID)
				pt.updateStats(res)
				resChan <- res
			}
		}()
	}
	for _, cfg := range configs {
		cfgChan <- cfg
	}
	close(cfgChan)
	go func() {
		wg.Wait()
		close(resChan)
	}()
	var results []*TestResultData
	success := 0
	for r := range resChan {
		results = append(results, r)
		if r.Result == ResultSuccess {
			success++
		}
	}
	log.Printf("Batch %d completed: %d/%d successful (%.1f%%)",
		batchID, success, len(configs), float64(success)/float64(len(configs))*100)
	// ⚠️  hard cleanup + grace
	pt.hardCleanupBatch()
	time.Sleep(500 * time.Millisecond)
	return results
}

/* --------------------  HARD CLEANUP  -------------------- */

func (pt *ProxyTester) hardCleanupBatch() {
	// kill any leftover xray
	_ = exec.Command("pkill", "-f", "xray.*xray-config").Run()
	time.Sleep(300 * time.Millisecond)
}

/* --------------------  STATS & SAVE  -------------------- */

func (pt *ProxyTester) updateStats(res *TestResultData) {
	if protoStats, ok := pt.stats.Load(res.Config.Protocol); ok {
		m := protoStats.(map[string]*int64)
		atomic.AddInt64(m["total"], 1)
		if res.Result == ResultSuccess {
			atomic.AddInt64(m["success"], 1)
		} else {
			atomic.AddInt64(m["failed"], 1)
		}
	}
	if overall, ok := pt.stats.Load("overall"); ok {
		m := overall.(map[string]*int64)
		atomic.AddInt64(m["total"], 1)
		switch res.Result {
		case ResultSuccess:
			atomic.AddInt64(m["success"], 1)
		case ResultParseError:
			atomic.AddInt64(m["parse_errors"], 1)
			atomic.AddInt64(m["failed"], 1)
		case ResultSyntaxError:
			atomic.AddInt64(m["syntax_errors"], 1)
			atomic.AddInt64(m["failed"], 1)
		case ResultConnectionError:
			atomic.AddInt64(m["connection_errors"], 1)
			atomic.AddInt64(m["failed"], 1)
		case ResultTimeout:
			atomic.AddInt64(m["timeouts"], 1)
			atomic.AddInt64(m["failed"], 1)
		case ResultNetworkError:
			atomic.AddInt64(m["network_errors"], 1)
			atomic.AddInt64(m["failed"], 1)
		default:
			atomic.AddInt64(m["failed"], 1)
		}
	}
}

func (pt *ProxyTester) saveConfigImmediately(res *TestResultData) {
	if res.Result != ResultSuccess {
		return
	}
	proto := res.Config.Protocol
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := pt.createWorkingConfigLine(res)
	url := pt.createConfigURL(res)

	if f, ok := pt.outputFiles[proto]; ok {
		fmt.Fprintf(f, "# %s  %.3fs  %s\n%s\n\n", ts, *res.ResponseTime, res.ExternalIP, line)
		f.Sync()
	}
	if f, ok := pt.urlFiles[proto]; ok {
		fmt.Fprintf(f, "# %s  %.3fs  %s\n%s\n\n", ts, *res.ResponseTime, res.ExternalIP, url)
		f.Sync()
	}
	if pt.generalJSONFile != nil {
		fmt.Fprintf(pt.generalJSONFile, "# [%s]  %s  %.3fs  %s\n%s\n\n", strings.ToUpper(string(proto)), ts, *res.ResponseTime, res.ExternalIP, line)
		pt.generalJSONFile.Sync()
	}
	if pt.generalURLFile != nil {
		fmt.Fprintf(pt.generalURLFile, "# [%s]  %s  %.3fs  %s\n%s\n\n", strings.ToUpper(string(proto)), ts, *res.ResponseTime, res.ExternalIP, url)
		pt.generalURLFile.Sync()
	}
}

func (pt *ProxyTester) createWorkingConfigLine(res *TestResultData) string {
	c := &res.Config
	m := map[string]interface{}{
		"protocol": string(c.Protocol), "server": c.Server, "port": c.Port,
		"network": c.Network, "tls": c.TLS, "remarks": c.Remarks,
		"test_time": res.ResponseTime, "external_ip": res.ExternalIP,
	}
	switch c.Protocol {
	case ProtocolShadowsocks:
		m["method"] = c.Method
		m["password"] = c.Password
	case ProtocolVMess:
		m["uuid"] = c.UUID
		m["alterId"] = c.AlterID
		m["cipher"] = c.Cipher
		m["path"] = c.Path
		m["host"] = c.Host
		m["sni"] = c.SNI
	case ProtocolVLESS:
		m["uuid"] = c.UUID
		m["flow"] = c.Flow
		m["encryption"] = c.Encrypt
		m["path"] = c.Path
		m["host"] = c.Host
		m["sni"] = c.SNI
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (pt *ProxyTester) createConfigURL(res *TestResultData) string {
	c := &res.Config
	switch c.Protocol {
	case ProtocolShadowsocks:
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Method, c.Password)))
		rem := url.QueryEscape(c.Remarks)
		if rem == "" {
			rem = fmt.Sprintf("SS-%s", c.Server)
		}
		return fmt.Sprintf("ss://%s@%s:%d#%s", auth, c.Server, c.Port, rem)
	case ProtocolVMess:
		vm := map[string]interface{}{
			"v": "2", "ps": c.Remarks, "add": c.Server, "port": strconv.Itoa(c.Port),
			"id": c.UUID, "aid": strconv.Itoa(c.AlterID), "scy": c.Cipher,
			"net": c.Network, "type": c.HeaderType, "host": c.Host, "path": c.Path,
			"tls": c.TLS, "sni": c.SNI, "alpn": c.ALPN,
		}
		if vm["ps"] == "" {
			vm["ps"] = fmt.Sprintf("VMess-%s", c.Server)
		}
		b, _ := json.Marshal(vm)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	case ProtocolVLESS:
		val := url.Values{}
		if c.Encrypt != "" && c.Encrypt != "none" {
			val.Add("encryption", c.Encrypt)
		}
		if c.Flow != "" {
			val.Add("flow", c.Flow)
		}
		if c.TLS != "" {
			val.Add("security", c.TLS)
		}
		if c.Network != "" && c.Network != "tcp" {
			val.Add("type", c.Network)
		}
		if c.Host != "" {
			val.Add("host", c.Host)
		}
		if c.Path != "" {
			val.Add("path", c.Path)
		}
		if c.SNI != "" {
			val.Add("sni", c.SNI)
		}
		if c.ALPN != "" {
			val.Add("alpn", c.ALPN)
		}
		if c.ServiceName != "" {
			val.Add("serviceName", c.ServiceName)
		}
		if c.Fingerprint != "" {
			val.Add("fp", c.Fingerprint)
		}
		q := ""
		if len(val) > 0 {
			q = "?" + val.Encode()
		}
		rem := url.QueryEscape(c.Remarks)
		if rem == "" {
			rem = fmt.Sprintf("VLESS-%s", c.Server)
		}
		return fmt.Sprintf("vless://%s@%s:%d%s#%s", c.UUID, c.Server, c.Port, q, rem)
	}
	return fmt.Sprintf("%s://%s:%d", c.Protocol, c.Server, c.Port)
}

/* --------------------  RUN ALL TESTS  -------------------- */

func (pt *ProxyTester) RunTests(configs []ProxyConfig) []*TestResultData {
	if len(configs) == 0 {
		log.Println("No configurations to test")
		return nil
	}
	sigC := make(chan os.Signal, 1)
	signal.Notify(sigC, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigC
		log.Println("Shutdown signal received, cleaning up...")
		pt.Cleanup()
		os.Exit(0)
	}()

	total := len(configs)
	log.Printf("Starting comprehensive proxy testing for %d configurations", total)
	log.Printf("Settings: %d workers, %v timeout, batch size: %d", pt.config.MaxWorkers, pt.config.Timeout, pt.config.BatchSize)

	var all []*TestResultData
	for batchIdx := 0; batchIdx < total; batchIdx += pt.config.BatchSize {
		end := batchIdx + pt.config.BatchSize
		if end > total {
			end = total
		}
		batch := configs[batchIdx:end]
		batchID := (batchIdx / pt.config.BatchSize) + 1
		log.Printf("Processing batch %d (%d configs)...", batchID, len(batch))
		batchRes := pt.TestConfigs(batch, batchID)
		all = append(all, batchRes...)
		pt.saveResults(all)
		if end < total {
			time.Sleep(500 * time.Millisecond)
		}
	}
	pt.printFinalSummary(all)
	return all
}

func (pt *ProxyTester) saveResults(results []*TestResultData) {
	if err := os.MkdirAll(pt.config.LogDir, 0755); err != nil {
		log.Printf("Failed to create log directory: %v", err)
		return
	}
	f, err := os.Create(filepath.Join(pt.config.LogDir, "test_results.json"))
	if err != nil {
		log.Printf("Failed to save results: %v", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(results)
}

func (pt *ProxyTester) printFinalSummary(results []*TestResultData) {
	total := len(results)
	success := 0
	var times []float64
	for _, r := range results {
		if r.Result == ResultSuccess {
			success++
			if r.ResponseTime != nil {
				times = append(times, *r.ResponseTime)
			}
		}
	}
	log.Println(strings.Repeat("=", 60))
	log.Println("FINAL TESTING SUMMARY")
	log.Println(strings.Repeat("=", 60))
	log.Printf("Total configurations tested: %d", total)
	log.Printf("Successful connections: %d", success)
	log.Printf("Failed connections: %d", total-success)
	if total > 0 {
		log.Printf("Success rate: %.2f%%", float64(success)/float64(total)*100)
	}
	log.Println("\nProtocol Breakdown:")
	for _, proto := range []ProxyProtocol{ProtocolShadowsocks, ProtocolVMess, ProtocolVLESS} {
		if v, ok := pt.stats.Load(proto); ok {
			m := v.(map[string]*int64)
			tot := atomic.LoadInt64(m["total"])
			succ := atomic.LoadInt64(m["success"])
			if tot > 0 {
				log.Printf("  %-12s: %4d/%4d (%.1f%%)", strings.ToUpper(string(proto)), succ, tot, float64(succ)/float64(tot)*100)
			}
		}
	}
	if n := len(times); n > 0 {
		var sum float64
		min, max := times[0], times[0]
		for _, t := range times {
			sum += t
			if t < min {
				min = t
			}
			if t > max {
				max = t
			}
		}
		avg := sum / float64(n)
		log.Println("\nResponse Times (successful only):")
		log.Printf("  Average: %.3fs", avg)
		log.Printf("  Minimum: %.3fs", min)
		log.Printf("  Maximum: %.3fs", max)
	}
	log.Println(strings.Repeat("=", 60))
}

func (pt *ProxyTester) Cleanup() {
	for _, f := range pt.outputFiles {
		if f != nil {
			f.Close()
		}
	}
	for _, f := range pt.urlFiles {
		if f != nil {
			f.Close()
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

/* ==========================  MAIN  ========================== */

func setupDirectories(cfg *Config) error {
	dirs := []string{
		cfg.DataDir,
		cfg.LogDir,
		filepath.Join(cfg.DataDir, "working_json"),
		filepath.Join(cfg.DataDir, "working_url"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", d, err)
		}
	}
	return nil
}

func main() {
	cfg := NewDefaultConfig()
	if err := setupDirectories(cfg); err != nil {
		log.Fatalf("Failed to setup directories: %v", err)
	}
	tester, err := NewProxyTester(cfg)
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
	for proto, path := range configFiles {
		if _, err := os.Stat(path); err == nil {
			cfgs, err := tester.LoadConfigsFromJSON(path, proto)
			if err != nil {
				log.Printf("Failed to load %s configs: %v", proto, err)
			} else {
				allConfigs = append(allConfigs, cfgs...)
			}
		} else {
			log.Printf("Config file not found: %s", path)
		}
	}
	if len(allConfigs) == 0 {
		log.Println("No valid configurations found to test")
		return
	}
	log.Printf("Total unique configurations for testing: %d", len(allConfigs))
	results := tester.RunTests(allConfigs)
	working := 0
	for _, r := range results {
		if r.Result == ResultSuccess {
			working++
		}
	}
	if working > 0 {
		log.Printf("\nWorking configurations saved to:")
		log.Printf("  JSON: %s/working_json/working_*.txt", cfg.DataDir)
		log.Printf("  URL:  %s/working_url/working_*_urls.txt", cfg.DataDir)
		log.Printf("  All configs (JSON): %s/working_json/working_all_configs.txt", cfg.DataDir)
		log.Printf("  All configs (URL):  %s/working_url/working_all_urls.txt", cfg.DataDir)
	} else {
		log.Println("No working configurations found")
	}
}
