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
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"


)

// Note: All shared types moved to utils.go

// JSON file structures for loading configs
type ShadowsocksJSON struct {
	Metadata struct {
		Protocol     string `json:"protocol"`
		GeneratedAt  string `json:"generated_at"`
		TotalConfigs int    `json:"total_configs"`
	} `json:"metadata"`
	Configs []struct {
		Type       string `json:"type"`
		Server     string `json:"server"`
		Port       int    `json:"port"`
		Method     string `json:"method"`
		Password   string `json:"password"`
		Remarks    string `json:"remarks"`
		Plugin     string `json:"plugin"`
		PluginOpts string `json:"plugin_opts"`
		NonStd     bool   `json:"non_standard"`
		RawParams  map[string]interface{} `json:"raw_params"`
		ID         int    `json:"id"`
		LineNumber int    `json:"line_number"`
		ParsedAt   string `json:"parsed_at"`
	} `json:"configs"`
}

type VMessJSON struct {
	Metadata struct {
		Protocol     string `json:"protocol"`
		GeneratedAt  string `json:"generated_at"`
		TotalConfigs int    `json:"total_configs"`
	} `json:"metadata"`
	Configs []struct {
		Type        string                 `json:"type"`
		Server      string                 `json:"server"`
		Port        int                    `json:"port"`
		UUID        string                 `json:"uuid"`
		AlterID     int                    `json:"alterId"`
		Cipher      string                 `json:"cipher"`
		Network     string                 `json:"network"`
		TLS         string                 `json:"tls"`
		SNI         string                 `json:"sni"`
		Path        string                 `json:"path"`
		Host        string                 `json:"host"`
		Remarks     string                 `json:"remarks"`
		ALPN        string                 `json:"alpn"`
		Fingerprint string                 `json:"fingerprint"`
		TypeNetwork string                 `json:"type_network"`
		Security    string                 `json:"security"`
		RawConfig   map[string]interface{} `json:"raw_config"`
		ID          int                    `json:"id"`
		LineNumber  int                    `json:"line_number"`
		ParsedAt    string                 `json:"parsed_at"`
	} `json:"configs"`
}

type VLessJSON struct {
	Metadata struct {
		Protocol     string `json:"protocol"`
		GeneratedAt  string `json:"generated_at"`
		TotalConfigs int    `json:"total_configs"`
	} `json:"metadata"`
	Configs []struct {
		Type        string                 `json:"type"`
		Server      string                 `json:"server"`
		Port        int                    `json:"port"`
		UUID        string                 `json:"uuid"`
		Flow        string                 `json:"flow"`
		Encryption  string                 `json:"encryption"`
		Network     string                 `json:"network"`
		TLS         string                 `json:"tls"`
		SNI         string                 `json:"sni"`
		Path        string                 `json:"path"`
		Host        string                 `json:"host"`
		Remarks     string                 `json:"remarks"`
		ALPN        string                 `json:"alpn"`
		Fingerprint string                 `json:"fingerprint"`
		HeaderType  string                 `json:"headerType"`
		ServiceName string                 `json:"serviceName"`
		RawParams   map[string]interface{} `json:"raw_params"`
		ID          int                    `json:"id"`
		LineNumber  int                    `json:"line_number"`
		ParsedAt    string                 `json:"parsed_at"`
	} `json:"configs"`
}

// PortManager moved to utils.go

// Enhanced Network tester with connection pooling and circuit breaker
type NetworkTester struct {
	timeout         time.Duration
	testURLs        []string
	clientPool      *HTTPClientPool
	circuitBreaker  *CircuitBreaker
	rateLimiter     *RateLimiter
	retryManager    *SmartRetry
	bufferPool      *BufferPool
	metrics         *TestMetrics
	config          *Config
}

func NewNetworkTester(timeout time.Duration, config *Config) *NetworkTester {
	circuitBreaker := NewCircuitBreaker(config.Performance.CircuitBreakerConfig)
	circuitBreaker.enabled = config.Performance.EnableCircuitBreaker

	nt := &NetworkTester{
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
		clientPool:     NewHTTPClientPool(timeout, config),
		circuitBreaker: circuitBreaker,
		rateLimiter:    NewRateLimiter(config.Performance.RateLimitConfig),
		retryManager:   NewSmartRetry(config.ProxyTester.RetryConfig),
		bufferPool:     NewBufferPool(config.Performance.MemoryOptimization.BufferSize),
		metrics:        NewTestMetrics(),
		config:         config,
	}

	// Configure circuit breaker state change callback (only if enabled)
	if config.Performance.EnableCircuitBreaker {
		nt.circuitBreaker.onStateChange = func(state CircuitState) {
			log.Printf("Circuit breaker state changed to: %v", state)
		}
	}

	return nt
}

func (nt *NetworkTester) TestProxyConnection(proxyPort int) (bool, string, float64) {
	startTime := time.Now()

	// Check circuit breaker state (only if enabled)
	if nt.config.Performance.EnableCircuitBreaker && nt.circuitBreaker.GetState() == StateOpen {
		nt.metrics.UpdateFailure("circuit_breaker_open")
		return false, "", time.Since(startTime).Seconds()
	}

	// Rate limiting
	if !nt.rateLimiter.Allow() {
		nt.metrics.UpdateFailure("rate_limited")
		return false, "", time.Since(startTime).Seconds()
	}

	// Check if proxy port is responsive
	if !nt.isProxyResponsive(proxyPort) {
		nt.metrics.UpdateFailure("proxy_not_responsive")
		return false, "", time.Since(startTime).Seconds()
	}

	// Test with multiple URLs using smart retry
	var lastErr error
	success, ip, responseTime := false, "", 0.0

	err := nt.retryManager.Execute(func() error {
		var testErr error
		success, ip, responseTime, testErr = nt.testWithMultipleURLs(proxyPort)
		if !success {
			lastErr = testErr
			return testErr
		}
		return nil
	})

	totalTime := time.Since(startTime).Seconds()

	if err != nil {
		nt.metrics.UpdateFailure(fmt.Sprintf("test_failed: %v", lastErr))
		return false, "", totalTime
	}

	nt.metrics.UpdateSuccess(responseTime * 1000) // Convert to milliseconds
	return success, ip, responseTime
}

func (nt *NetworkTester) testWithMultipleURLs(proxyPort int) (bool, string, float64, error) {
	// Test with multiple URLs
	testCount := 6
	if len(nt.testURLs) < testCount {
		testCount = len(nt.testURLs)
	}

	// Shuffle URLs for better distribution
	shuffled := make([]string, len(nt.testURLs))
	copy(shuffled, nt.testURLs)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	var lastErr error
	for i := 0; i < testCount; i++ {
		err := nt.circuitBreaker.Call(func() error {
			success, _, _ := nt.singleTest(proxyPort, shuffled[i])
			if success {
				return nil
			}
			return fmt.Errorf("test failed for URL: %s", shuffled[i])
		})

		if err == nil {
			// Success case handled in singleTest
			return true, "", 0, nil
		}
		lastErr = err
	}

	return false, "", 0, lastErr
}

func (nt *NetworkTester) isProxyResponsive(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (nt *NetworkTester) singleTest(proxyPort int, testURL string) (bool, string, float64) {
	startTime := time.Now()

	// Get client from pool
	client, err := nt.clientPool.GetClient(proxyPort)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}
	defer nt.clientPool.PutClient(client)

	// Create request
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}

	// Set headers for better compatibility
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "", time.Since(startTime).Seconds()
	}

	// Use buffer pool for reading response
	buf := nt.bufferPool.Get()
	defer nt.bufferPool.Put(buf)

	// Read response body efficiently
	var bodyBytes []byte
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			bodyBytes = append(bodyBytes, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, "", time.Since(startTime).Seconds()
		}
	}

	responseTime := time.Since(startTime).Seconds()
	ipText := strings.TrimSpace(string(bodyBytes))

	// Handle JSON responses
	if strings.Contains(resp.Header.Get("Content-Type"), "json") {
		var data map[string]interface{}
		if json.Unmarshal(bodyBytes, &data) == nil {
			if origin, ok := data["origin"].(string); ok {
				ipText = origin
			} else if ip, ok := data["ip"].(string); ok {
				ipText = ip
			}
		}
	}

	// Validate IP format
	if net.ParseIP(ipText) != nil {
		return true, ipText, responseTime
	}

	return false, "", responseTime
}

// Xray config generator
type XrayConfigGenerator struct {
	xrayPath string
}

func NewXrayConfigGenerator(xrayPath string) *XrayConfigGenerator {
	if xrayPath == "" {
		xrayPath = findXrayExecutable()
	}
	log.Printf("Using Xray path: %s", xrayPath)
	return &XrayConfigGenerator{xrayPath: xrayPath}
}

func findXrayExecutable() string {
	// First try system-wide installations
	systemPaths := []string{"/usr/local/bin/xray", "/usr/bin/xray"}
	for _, path := range systemPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Then try PATH lookup
	if path, err := exec.LookPath("xray"); err == nil {
		return path
	}

	// Finally try local paths (OS-specific)
	var localPaths []string
	if runtime.GOOS == "windows" {
		localPaths = []string{"./xray.exe", "xray.exe"}
	} else {
		localPaths = []string{"./xray", "xray"}
	}

	for _, path := range localPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Return OS-appropriate default
	if runtime.GOOS == "windows" {
		return "./xray.exe"
	}
	return "./xray"
}

func (xcg *XrayConfigGenerator) ValidateXray() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
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
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
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

	// Configure stream settings
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

	// TLS settings
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

// ProcessManager moved to utils.go

// Enhanced Main tester with adaptive configuration and monitoring
type ProxyTester struct {
	// Configuration
	config            *Config
	xrayPath          string
	maxWorkers        int
	timeout           time.Duration
	batchSize         int
	incrementalSave   bool

	// Enhanced components
	portManager       *PortManager
	processManager    *ProcessManager
	networkTester     *NetworkTester
	configGenerator   *XrayConfigGenerator

	// New enhancement components
	healthChecker     *HealthChecker
	metrics           *TestMetrics
	progressTracker   *ProgressTracker
	adaptiveConfig    *AdaptiveConfig
	circuitBreaker    *CircuitBreaker
	rateLimiter       *RateLimiter
	gracefulShutdown  *GracefulShutdown

	// Output files
	outputFiles       map[ProxyProtocol]*os.File
	urlFiles          map[ProxyProtocol]*os.File

	// General output files for all successful configs
	generalJSONFile   *os.File
	generalURLFile    *os.File

	// Statistics
	stats             sync.Map
	results           []TestResultData
	resultsMu         sync.Mutex

	// Runtime optimization
	bufferPool        *BufferPool
	workerPool        chan struct{}
}

func NewProxyTester(configPath string) (*ProxyTester, error) {
	// Load configuration
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize enhanced proxy tester
	pt := &ProxyTester{
		config:          config,
		xrayPath:        config.ProxyTester.XrayPath,
		maxWorkers:      config.ProxyTester.MaxWorkers,
		timeout:         config.ProxyTester.Timeout,
		batchSize:       config.ProxyTester.BatchSize,
		incrementalSave: config.ProxyTester.IncrementalSave,

		// Enhanced components
		portManager:     NewPortManager(config.ProxyTester.PortRange.Start, config.ProxyTester.PortRange.End, config),
		processManager:  NewProcessManager(),
		networkTester:   NewNetworkTester(config.ProxyTester.Timeout, config),
		configGenerator: NewXrayConfigGenerator(config.ProxyTester.XrayPath),

		// New enhancement components
		healthChecker:    NewHealthChecker(),
		metrics:          NewTestMetrics(),
		adaptiveConfig:   NewAdaptiveConfig(),
		circuitBreaker:   NewCircuitBreaker(config.Performance.CircuitBreakerConfig),
		rateLimiter:      NewRateLimiter(config.Performance.RateLimitConfig),
		gracefulShutdown: NewGracefulShutdown(30 * time.Second),

		// Output files
		outputFiles: make(map[ProxyProtocol]*os.File),
		urlFiles:    make(map[ProxyProtocol]*os.File),

		// Runtime optimization
		bufferPool: NewBufferPool(config.Performance.MemoryOptimization.BufferSize),
		workerPool: make(chan struct{}, config.ProxyTester.MaxWorkers),
	}

	// Add health checks
	pt.healthChecker.AddCheck(NewMemoryHealthCheck(1024)) // 1GB limit
	pt.healthChecker.AddCheck(NewDiskHealthCheck(config.Common.OutputDir, 1)) // 1GB minimum

	// Setup cleanup functions for graceful shutdown
	pt.gracefulShutdown.AddCleanupFunc(func() error {
		pt.Cleanup()
		return nil
	})

	// Validate Xray
	if err := pt.configGenerator.ValidateXray(); err != nil {
		return nil, fmt.Errorf("xray validation failed: %w", err)
	}

	// Initialize statistics
	pt.initStats()

	// Setup incremental save files if enabled
	if pt.incrementalSave {
		if err := pt.setupIncrementalSave(); err != nil {
			log.Printf("Warning: Failed to setup incremental save: %v", err)
			pt.incrementalSave = false
		}
	}

	// Enable GC optimization if configured
	if config.Performance.MemoryOptimization.EnableGCOptimization {
		runtime.GC()
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	log.Printf("Enhanced ProxyTester initialized with %d workers, circuit breaker: %v, rate limiting: %v",
		pt.maxWorkers, config.Performance.EnableCircuitBreaker, config.Performance.RateLimitConfig.Enabled)

	return pt, nil
}

// NewProxyTesterWithDefaults creates a ProxyTester with default configuration
func NewProxyTesterWithDefaults() (*ProxyTester, error) {
	return NewProxyTester("")
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
	// Create directories if they don't exist
	os.MkdirAll("../data/working_json", 0755)
	os.MkdirAll("../data/working_url", 0755)

	protocols := map[ProxyProtocol]string{
		ProtocolShadowsocks: "shadowsocks",
		ProtocolVMess:       "vmess",
		ProtocolVLESS:       "vless",
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	for protocol, name := range protocols {
		// JSON format files
		jsonFile, err := os.Create(fmt.Sprintf("../data/working_json/working_%s.txt", name))
		if err != nil {
			return err
		}

		jsonFile.WriteString(fmt.Sprintf("# Working %s Configurations (JSON Format)\n", strings.ToUpper(name)))
		jsonFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
		jsonFile.WriteString("# Format: Each line contains one working configuration in JSON\n\n")
		pt.outputFiles[protocol] = jsonFile

		// URL format files
		urlFile, err := os.Create(fmt.Sprintf("../data/working_url/working_%s_urls.txt", name))
		if err != nil {
			return err
		}

		urlFile.WriteString(fmt.Sprintf("# Working %s Configurations (URL Format)\n", strings.ToUpper(name)))
		urlFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
		urlFile.WriteString("# Format: Each line contains one working configuration as URL\n\n")
		pt.urlFiles[protocol] = urlFile
	}

	// Create general output files for all successful configs
	generalJSONFile, err := os.Create("../data/working_json/working_all_configs.txt")
	if err != nil {
		return err
	}
	generalJSONFile.WriteString("# All Working Configurations (JSON Format)\n")
	generalJSONFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
	generalJSONFile.WriteString("# Format: Each line contains one working configuration in JSON\n")
	generalJSONFile.WriteString("# Protocols: Shadowsocks, VMess, VLESS\n\n")
	pt.generalJSONFile = generalJSONFile

	generalURLFile, err := os.Create("../data/working_url/working_all_urls.txt")
	if err != nil {
		return err
	}
	generalURLFile.WriteString("# All Working Configurations (URL Format)\n")
	generalURLFile.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
	generalURLFile.WriteString("# Format: Each line contains one working configuration as URL\n")
	generalURLFile.WriteString("# Protocols: Shadowsocks, VMess, VLESS\n\n")
	pt.generalURLFile = generalURLFile

	log.Println("Incremental save files initialized (JSON + URL formats + General files)")
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
	// Simple structure for parsed_configs/ss.json
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
			Network:  "tcp", // Default
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
	// Simple structure for parsed_configs/vmess.json
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
		// Convert AlterId from string to int
		alterId := 0
		if configData.AlterId != "" {
			if aid, err := strconv.Atoi(configData.AlterId); err == nil {
				alterId = aid
			}
		}

		config := ProxyConfig{
			Protocol: ProtocolVMess,
			Server:   configData.Address,
			Port:     configData.Port,
			UUID:     configData.ID,
			AlterID:  alterId,
			Cipher:   configData.Security,
			Network:  configData.Network,
			TLS:      configData.TLS,
			SNI:      configData.SNI,
			Path:     configData.Path,
			Host:     configData.Host,
			Remarks:  configData.Name,
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
	// Simple structure for parsed_configs/vless.json
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
			Encrypt:  "none", // Default for VLESS
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
	// Basic validation
	if config.Server == "" || config.Port <= 0 || config.Port > 65535 {
		return false
	}

	// Protocol-specific validation
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

		// Cleanup
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

	// Get available port
	var ok bool
	proxyPort, ok = pt.portManager.GetAvailablePort()
	if !ok || proxyPort == 0 {
		result.Result = ResultPortConflict
		return result
	}
	result.ProxyPort = &proxyPort

	// Generate Xray config
	xrayConfig, err := pt.configGenerator.GenerateConfig(config, proxyPort)
	if err != nil {
		result.Result = ResultInvalidConfig
		result.ErrorMessage = err.Error()
		return result
	}

	// Write config to temporary file
	configFile, err = pt.writeConfigToTempFile(xrayConfig)
	if err != nil {
		result.Result = ResultInvalidConfig
		result.ErrorMessage = err.Error()
		return result
	}

	// Test config syntax
	if err := pt.testConfigSyntax(configFile); err != nil {
		result.Result = ResultSyntaxError
		result.ErrorMessage = err.Error()
		return result
	}

	// Start Xray process
	process, err = pt.startXrayProcess(configFile)
	if err != nil {
		result.Result = ResultConnectionError
		result.ErrorMessage = err.Error()
		return result
	}

	pt.processManager.RegisterProcess(process.Process.Pid, process)

	// Wait for Xray to start
	time.Sleep(2 * time.Second)

	// Check if process is still running
	if process.ProcessState != nil && process.ProcessState.Exited() {
		result.Result = ResultConnectionError
		result.ErrorMessage = "Xray process terminated"
		return result
	}

	// Test connection through proxy
	success, externalIP, responseTime := pt.networkTester.TestProxyConnection(proxyPort)
	if success {
		result.Result = ResultSuccess
		result.ExternalIP = externalIP
		result.ResponseTime = &responseTime

		// Save immediately if incremental save is enabled
		if pt.incrementalSave {
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
	// Create temp file
	tmpFile, err := os.CreateTemp("", "xray-config-*.json")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	// Write config as JSON
	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

func (pt *ProxyTester) testConfigSyntax(configFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
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

	// Redirect stdout and stderr to discard
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

	// Save JSON format
	if file, ok := pt.outputFiles[protocol]; ok {
		configLine := pt.createWorkingConfigLine(result)
		fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s\n",
			timestamp, *result.ResponseTime, result.ExternalIP)
		fmt.Fprintf(file, "%s\n\n", configLine)
		file.Sync()
	}

	// Save URL format
	if file, ok := pt.urlFiles[protocol]; ok {
		configURL := pt.createConfigURL(result)
		fmt.Fprintf(file, "# Tested at: %s | Response: %.3fs | IP: %s\n",
			timestamp, *result.ResponseTime, result.ExternalIP)
		fmt.Fprintf(file, "%s\n\n", configURL)
		file.Sync()
	}

	// Save to general JSON file
	if pt.generalJSONFile != nil {
		configLine := pt.createWorkingConfigLine(result)
		fmt.Fprintf(pt.generalJSONFile, "# [%s] Tested at: %s | Response: %.3fs | IP: %s\n",
			strings.ToUpper(string(protocol)), timestamp, *result.ResponseTime, result.ExternalIP)
		fmt.Fprintf(pt.generalJSONFile, "%s\n\n", configLine)
		pt.generalJSONFile.Sync()
	}

	// Save to general URL file
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
	// Update protocol-specific stats
	if protocolStats, ok := pt.stats.Load(result.Config.Protocol); ok {
		stats := protocolStats.(map[string]*int64)
		atomic.AddInt64(stats["total"], 1)
		if result.Result == ResultSuccess {
			atomic.AddInt64(stats["success"], 1)
		} else {
			atomic.AddInt64(stats["failed"], 1)
		}
	}

	// Update overall stats
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

	// Health check before starting
	if healthResults := pt.healthChecker.CheckAll(); len(healthResults) > 0 {
		for name, err := range healthResults {
			if err != nil {
				log.Printf("Health check failed for %s: %v", name, err)
			}
		}
	}

	// Adaptive worker count based on performance
	maxWorkers := pt.adaptiveConfig.SuggestWorkerCount(pt.maxWorkers)
	if len(configs) < maxWorkers {
		maxWorkers = len(configs)
	}

	log.Printf("Using %d workers (adaptive: %d, original: %d)", maxWorkers, maxWorkers, pt.maxWorkers)

	configChan := make(chan ProxyConfig, len(configs))
	resultChan := make(chan *TestResultData, len(configs))

	// Initialize progress tracking
	progressTracker := NewProgressTracker(int64(len(configs)))

	// Start workers with enhanced error handling
	var wg sync.WaitGroup
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for config := range configChan {
				// Worker pool semaphore
				pt.workerPool <- struct{}{}

				// Rate limiting
				if !pt.rateLimiter.Allow() {
					log.Printf("Worker %d: Rate limited, skipping config %s:%d", workerID, config.Server, config.Port)
					<-pt.workerPool
					continue
				}

				// Circuit breaker check (only if enabled)
				if pt.config.Performance.EnableCircuitBreaker && pt.circuitBreaker.GetState() == StateOpen {
					log.Printf("Worker %d: Circuit breaker open, skipping config %s:%d", workerID, config.Server, config.Port)
					<-pt.workerPool
					continue
				}

				// Test configuration with circuit breaker
				var result *TestResultData
				err := pt.circuitBreaker.Call(func() error {
					result = pt.TestSingleConfig(&config, batchID)
					if result.Result != ResultSuccess {
						return fmt.Errorf("test failed: %s", result.ErrorMessage)
					}
					return nil
				})

				if err != nil && result == nil {
					// Create failed result if circuit breaker prevented execution
					result = &TestResultData{
						Config:       config,
						Result:       ResultNetworkError,
						ErrorMessage: err.Error(),
						BatchID:      &batchID,
					}
				}

				pt.updateStats(result)
				pt.metrics.UpdateMemoryUsage()
				progressTracker.IncrementProgress()

				resultChan <- result
				<-pt.workerPool
			}
		}(i)
	}

	// Send configs to workers
	for _, config := range configs {
		configChan <- config
	}
	close(configChan)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results with monitoring
	var results []*TestResultData
	successCount := 0
	startTime := time.Now()

	for result := range resultChan {
		results = append(results, result)
		if result.Result == ResultSuccess {
			successCount++
		}

		// Periodic metrics update
		if len(results)%100 == 0 {
			pt.updateAdaptiveMetrics(results)
		}
	}

	// Final metrics update
	pt.updateAdaptiveMetrics(results)
	duration := time.Since(startTime)

	log.Printf("Batch %d completed: %d/%d successful (%.1f%%) in %v",
		batchID, successCount, len(configs), float64(successCount)/float64(len(configs))*100, duration)

	// Log circuit breaker stats
	failures, successes, state := pt.circuitBreaker.GetStats()
	log.Printf("Circuit breaker stats - Failures: %d, Successes: %d, State: %v", failures, successes, state)

	return results
}

// updateAdaptiveMetrics updates metrics for adaptive configuration
func (pt *ProxyTester) updateAdaptiveMetrics(results []*TestResultData) {
	if len(results) == 0 {
		return
	}

	successCount := 0
	totalLatency := 0.0
	latencyCount := 0

	for _, result := range results {
		if result.Result == ResultSuccess {
			successCount++
			if result.ResponseTime != nil {
				totalLatency += *result.ResponseTime
				latencyCount++
			}
		}
	}

	successRate := float64(successCount) / float64(len(results)) * 100
	avgLatency := 0.0
	if latencyCount > 0 {
		avgLatency = totalLatency / float64(latencyCount) * 1000 // Convert to milliseconds
	}

	// Get memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	memoryUsage := float64(m.Alloc) / 1024 / 1024 / 1024 * 100 // Convert to GB percentage

	pt.adaptiveConfig.UpdateMetrics(successRate, avgLatency, memoryUsage)
}

func (pt *ProxyTester) RunTests(configs []ProxyConfig) []*TestResultData {
	if len(configs) == 0 {
		log.Println("No configurations to test")
		return nil
	}

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, initiating graceful shutdown...")
		if err := pt.gracefulShutdown.Shutdown(); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
		os.Exit(0)
	}()

	totalConfigs := len(configs)
	log.Printf("Starting enhanced proxy testing for %d configurations", totalConfigs)
	log.Printf("Settings: %d workers, %v timeout, batch size: %d", pt.maxWorkers, pt.timeout, pt.batchSize)
	log.Printf("Enhanced features: Circuit Breaker: %v, Rate Limiting: %v, Adaptive Config: enabled",
		pt.config.Performance.EnableCircuitBreaker, pt.config.Performance.RateLimitConfig.Enabled)

	// Initialize progress tracking
	pt.progressTracker = NewProgressTracker(int64(totalConfigs))

	var allResults []*TestResultData
	startTime := time.Now()

	// Adaptive batch size
	currentBatchSize := pt.batchSize

	// Process in batches with adaptive optimization
	for batchIdx := 0; batchIdx < totalConfigs; batchIdx += currentBatchSize {
		end := batchIdx + currentBatchSize
		if end > totalConfigs {
			end = totalConfigs
		}

		batch := configs[batchIdx:end]
		batchID := (batchIdx / currentBatchSize) + 1

		log.Printf("Processing batch %d (%d configs)...", batchID, len(batch))

		// Health check before each batch
		if healthResults := pt.healthChecker.CheckAll(); len(healthResults) > 0 {
			for name, err := range healthResults {
				if err != nil {
					log.Printf("Health check warning for %s: %v", name, err)
				}
			}
		}

		batchResults := pt.TestConfigs(batch, batchID)
		allResults = append(allResults, batchResults...)

		// Update overall progress
		pt.progressTracker.UpdateProgress(int64(len(allResults)))

		// Save intermediate results
		if pt.config.Common.EnableMetrics {
			pt.saveResults(allResults)
			pt.saveMetrics()
		}

		// Adaptive batch size adjustment
		if pt.config.QualityTester.AdaptiveTesting {
			newBatchSize := pt.adaptiveConfig.SuggestBatchSize(currentBatchSize)
			if newBatchSize != currentBatchSize {
				log.Printf("Adaptive batch size changed from %d to %d", currentBatchSize, newBatchSize)
				currentBatchSize = newBatchSize
			}
		}

		// Circuit breaker recovery delay (only if enabled)
		if pt.config.Performance.EnableCircuitBreaker && pt.circuitBreaker.GetState() == StateOpen {
			log.Println("Circuit breaker is open, waiting for recovery...")
			time.Sleep(5 * time.Second)
		}

		// Small delay between batches for resource management
		if end < totalConfigs {
			time.Sleep(time.Duration(500+len(batch)/10) * time.Millisecond)
		}

		// Memory cleanup every few batches
		if batchID%5 == 0 && pt.config.Performance.MemoryOptimization.EnableGCOptimization {
			runtime.GC()
		}
	}

	duration := time.Since(startTime)

	// Print enhanced final summary
	pt.printEnhancedFinalSummary(allResults, duration)

	// Save final metrics
	if pt.config.Common.EnableMetrics {
		pt.saveFinalMetrics(allResults, duration)
	}

	return allResults
}

// saveMetrics saves current metrics to file
func (pt *ProxyTester) saveMetrics() {
	total, successful, successRate, avgLatency := pt.metrics.GetStats()

	metricsData := map[string]interface{}{
		"timestamp":      time.Now(),
		"total_tests":    total,
		"successful":     successful,
		"success_rate":   successRate,
		"avg_latency_ms": avgLatency,
		"circuit_breaker": map[string]interface{}{
			"state":    pt.circuitBreaker.GetState(),
			"failures": 0, // Will be updated with actual values
		},
	}

	// Save to metrics file
	metricsFile := fmt.Sprintf("%s/metrics/realtime_metrics.json", pt.config.Common.OutputDir)
	os.MkdirAll(fmt.Sprintf("%s/metrics", pt.config.Common.OutputDir), 0755)

	if file, err := os.Create(metricsFile); err == nil {
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(metricsData)
	}
}

// saveFinalMetrics saves comprehensive final metrics
func (pt *ProxyTester) saveFinalMetrics(results []*TestResultData, duration time.Duration) {
	total, successful, successRate, avgLatency := pt.metrics.GetStats()
	failures, successes, cbState := pt.circuitBreaker.GetStats()

	finalMetrics := map[string]interface{}{
		"test_summary": map[string]interface{}{
			"total_configurations": len(results),
			"successful_tests":     successful,
			"failed_tests":         total - successful,
			"success_rate_percent": successRate,
			"total_duration":       duration.String(),
			"avg_latency_ms":       avgLatency,
		},
		"performance_metrics": map[string]interface{}{
			"tests_per_second":     float64(total) / duration.Seconds(),
			"avg_batch_time":       duration.Seconds() / float64((len(results)/pt.batchSize)+1),
			"memory_usage_mb":      0, // Will be updated
		},
		"circuit_breaker_stats": map[string]interface{}{
			"final_state":     cbState,
			"total_failures":  failures,
			"total_successes": successes,
		},
		"configuration": map[string]interface{}{
			"max_workers":      pt.maxWorkers,
			"batch_size":       pt.batchSize,
			"timeout_seconds":  pt.timeout.Seconds(),
			"circuit_breaker":  pt.config.Performance.EnableCircuitBreaker,
			"rate_limiting":    pt.config.Performance.RateLimitConfig.Enabled,
		},
	}

	// Add memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	finalMetrics["performance_metrics"].(map[string]interface{})["memory_usage_mb"] = float64(m.Alloc) / 1024 / 1024

	// Save final metrics
	metricsFile := fmt.Sprintf("%s/metrics/final_metrics.json", pt.config.Common.OutputDir)
	if file, err := os.Create(metricsFile); err == nil {
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(finalMetrics)
		log.Printf("Final metrics saved to: %s", metricsFile)
	}
}

func (pt *ProxyTester) saveResults(results []*TestResultData) {
	file, err := os.Create("../log/test_results.json")
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
	pt.printEnhancedFinalSummary(results, 0)
}

func (pt *ProxyTester) printEnhancedFinalSummary(results []*TestResultData, duration time.Duration) {
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

	log.Println("=" + strings.Repeat("=", 70))
	log.Println("ENHANCED PROXY TESTING FINAL SUMMARY")
	log.Println("=" + strings.Repeat("=", 70))
	log.Printf("Total configurations tested: %d", totalCount)
	log.Printf("Successful connections: %d", successCount)
	log.Printf("Failed connections: %d", totalCount-successCount)
	if totalCount > 0 {
		log.Printf("Success rate: %.2f%%", float64(successCount)/float64(totalCount)*100)
	}
	if duration > 0 {
		log.Printf("Total test duration: %v", duration)
		log.Printf("Tests per second: %.2f", float64(totalCount)/duration.Seconds())
	}

	// Enhanced metrics
	total, successful, successRate, avgLatency := pt.metrics.GetStats()
	log.Printf("Enhanced metrics - Total: %d, Successful: %d, Success Rate: %.1f%%, Avg Latency: %.1fms",
		total, successful, successRate, avgLatency)

	// Circuit breaker statistics
	failures, successes, cbState := pt.circuitBreaker.GetStats()
	log.Printf("Circuit Breaker - State: %v, Failures: %d, Successes: %d", cbState, failures, successes)

	// Protocol breakdown
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

	// Response time statistics
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

	// Memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("\nMemory Usage:")
	log.Printf("  Allocated: %.2f MB", float64(m.Alloc)/1024/1024)
	log.Printf("  Total Allocations: %.2f MB", float64(m.TotalAlloc)/1024/1024)
	log.Printf("  GC Cycles: %d", m.NumGC)

	// Performance recommendations
	log.Println("\nPerformance Insights:")
	if successRate < 50 {
		log.Println("  - Low success rate detected. Consider adjusting timeout or worker count.")
	}
	if avgLatency > 5000 {
		log.Println("  - High latency detected. Network conditions may be poor.")
	}
	if cbState == StateOpen {
		log.Println("  - Circuit breaker is open. Consider investigating network issues.")
	}

	log.Println("=" + strings.Repeat("=", 70))
}

func (pt *ProxyTester) Cleanup() {
	// Close output files
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

	// Close general output files
	if pt.generalJSONFile != nil {
		pt.generalJSONFile.Close()
	}
	if pt.generalURLFile != nil {
		pt.generalURLFile.Close()
	}

	// Cleanup processes
	pt.processManager.Cleanup()
}

func main() {
	// Configuration file path (can be passed as command line argument)
	configPath := ""
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	// Initialize enhanced tester with configuration
	tester, err := NewProxyTester(configPath)
	if err != nil {
		log.Fatalf("Failed to initialize enhanced tester: %v", err)
	}
	defer tester.Cleanup()

	// Configuration file paths (can be made configurable)
	configFiles := map[ProxyProtocol]string{
		ProtocolShadowsocks: "../config_collector/deduplicated_urls/ss.json",
		ProtocolVMess:       "../config_collector/deduplicated_urls/vmess.json",
		ProtocolVLESS:       "../config_collector/deduplicated_urls/vless.json",
	}

	var allConfigs []ProxyConfig

	// Load configurations for each protocol with enhanced error handling
	for protocol, filePath := range configFiles {
		if _, err := os.Stat(filePath); err == nil {
			log.Printf("Loading %s configurations from: %s", protocol, filePath)
			configs, err := tester.LoadConfigsFromJSON(filePath, protocol)
			if err != nil {
				log.Printf("Failed to load %s configs: %v", protocol, err)
				continue
			}

			log.Printf("Successfully loaded %d %s configurations", len(configs), protocol)
			allConfigs = append(allConfigs, configs...)
		} else {
			log.Printf("Configuration file not found: %s", filePath)
		}
	}

	if len(allConfigs) == 0 {
		log.Println("No valid configurations found to test")
		return
	}

	log.Printf("Total unique configurations loaded: %d", len(allConfigs))

	// Shuffle configurations for better load distribution
	rand.Shuffle(len(allConfigs), func(i, j int) {
		allConfigs[i], allConfigs[j] = allConfigs[j], allConfigs[i]
	})

	// Run enhanced tests with monitoring
	log.Println("Starting enhanced proxy testing with monitoring...")
	results := tester.RunTests(allConfigs)

	// Calculate final statistics
	workingConfigs := 0
	protocolStats := make(map[ProxyProtocol]int)

	for _, result := range results {
		if result.Result == ResultSuccess {
			workingConfigs++
			protocolStats[result.Config.Protocol]++
		}
	}

	// Enhanced final reporting
	log.Println("\n" + strings.Repeat("=", 60))
	log.Println("ENHANCED TESTING COMPLETE")
	log.Println(strings.Repeat("=", 60))

	if workingConfigs > 0 {
		log.Printf("✅ Successfully found %d working configurations!", workingConfigs)
		log.Println("\nWorking configurations by protocol:")
		for protocol, count := range protocolStats {
			log.Printf("  %s: %d configurations", strings.ToUpper(string(protocol)), count)
		}

		log.Printf("\nOutput files saved to:")
		log.Printf("  📁 JSON format: %s/working_json/", tester.config.Common.OutputDir)
		log.Printf("  📁 URL format: %s/working_url/", tester.config.Common.OutputDir)
		log.Printf("  📁 Metrics: %s/metrics/", tester.config.Common.OutputDir)

		if tester.config.Common.EnableMetrics {
			log.Printf("  📊 Real-time metrics: %s/metrics/realtime_metrics.json", tester.config.Common.OutputDir)
			log.Printf("  📊 Final metrics: %s/metrics/final_metrics.json", tester.config.Common.OutputDir)
		}
	} else {
		log.Println("❌ No working configurations found")
		log.Println("Consider:")
		log.Println("  - Adjusting timeout settings")
		log.Println("  - Checking network connectivity")
		log.Println("  - Reviewing configuration files")
	}

	// Save configuration template for future use
	if configPath == "" {
		templatePath := "config_template.yaml"
		if err := SaveConfig(tester.config, templatePath); err == nil {
			log.Printf("📝 Configuration template saved to: %s", templatePath)
		}
	}

	log.Println(strings.Repeat("=", 60))
}
