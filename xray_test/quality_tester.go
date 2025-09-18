package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

const (
	DefaultPortStart    = 21000
	DefaultPortEnd      = 30000
	DefaultConcurrent   = 8
	DefaultMaxConfigs   = 10000
	DefaultTimeout      = 25 * time.Second
	DefaultRetries      = 2
	ProcessKillTimeout  = 200 * time.Millisecond
	XrayStartupTimeout  = 3 * time.Second
	PortReleaseDelay    = 10 * time.Millisecond
	MaxLatencyMs        = 5000
	StabilityThreshold  = 0.75
)

type QualityScore int

const (
	ScoreExcellent QualityScore = 1
	ScoreVeryGood  QualityScore = 2
	ScoreGood      QualityScore = 3
	ScoreFair      QualityScore = 4
	ScorePoor      QualityScore = 5
)

type Config struct {
	PortStart       int           `json:"port_start"`
	PortEnd         int           `json:"port_end"`
	Concurrent      int           `json:"concurrent"`
	MaxConfigs      int           `json:"max_configs"`
	Timeout         time.Duration `json:"timeout"`
	MaxRetries      int           `json:"max_retries"`
	XrayPath        string        `json:"xray_path"`
	OutputPath      string        `json:"output_path"`
	TestCritical    bool          `json:"test_critical"`
}

func DefaultConfig() *Config {
	return &Config{
		PortStart:    DefaultPortStart,
		PortEnd:      DefaultPortEnd,
		Concurrent:   DefaultConcurrent,
		MaxConfigs:   DefaultMaxConfigs,
		Timeout:      DefaultTimeout,
		MaxRetries:   DefaultRetries,
		XrayPath:     findXrayExecutable(),
		OutputPath:   "../data/quality_results",
		TestCritical: true,
	}
}

type PortManager struct {
	startPort      int
	endPort        int
	availablePorts chan int
	usedPorts      sync.Map
	mu             sync.RWMutex
	ctx            context.Context
}

func NewPortManager(ctx context.Context, startPort, endPort int) *PortManager {
	pm := &PortManager{
		startPort:      startPort,
		endPort:        endPort,
		availablePorts: make(chan int, endPort-startPort+1),
		ctx:            ctx,
	}
	pm.initializePortPool()
	return pm
}

func (pm *PortManager) initializePortPool() {
	log.Printf("Initializing port pool (%d-%d)...", pm.startPort, pm.endPort)
	availableCount := 0

	for port := pm.startPort; port <= pm.endPort; port++ {
		if pm.isPortAvailable(port) {
			select {
			case pm.availablePorts <- port:
				availableCount++
			case <-pm.ctx.Done():
				return
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

func (pm *PortManager) GetAvailablePort() (int, error) {
	select {
	case port := <-pm.availablePorts:
		pm.usedPorts.Store(port, true)
		return port, nil
	case <-time.After(100 * time.Millisecond):
		return pm.findEmergencyPort()
	case <-pm.ctx.Done():
		return 0, pm.ctx.Err()
	}
}

func (pm *PortManager) findEmergencyPort() (int, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := 0; i < 100; i++ {
		port := pm.startPort + (i * 17) % (pm.endPort - pm.startPort + 1)
		if _, used := pm.usedPorts.Load(port); !used && pm.isPortAvailable(port) {
			pm.usedPorts.Store(port, true)
			return port, nil
		}
	}
	return 0, fmt.Errorf("no emergency port available")
}

func (pm *PortManager) ReleasePort(port int) {
	pm.usedPorts.Delete(port)
	go func() {
		time.Sleep(PortReleaseDelay)
		select {
		case pm.availablePorts <- port:
		case <-pm.ctx.Done():
		default:
		}
	}()
}

type ProcessManager struct {
	processes sync.Map
	mu        sync.RWMutex
	ctx       context.Context
}

func NewProcessManager(ctx context.Context) *ProcessManager {
	return &ProcessManager{ctx: ctx}
}

func (pm *ProcessManager) RegisterProcess(pid int, cmd *exec.Cmd) {
	pm.processes.Store(pid, cmd)
}

func (pm *ProcessManager) UnregisterProcess(pid int) {
	pm.processes.Delete(pid)
}

func (pm *ProcessManager) KillProcess(pid int) error {
	value, ok := pm.processes.Load(pid)
	if !ok {
		return fmt.Errorf("process not found")
	}

	cmd, ok := value.(*exec.Cmd)
	if !ok || cmd.Process == nil {
		return fmt.Errorf("invalid process")
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err == nil {
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(ProcessKillTimeout):
			cmd.Process.Kill()
		case <-pm.ctx.Done():
			cmd.Process.Kill()
		}
	} else {
		cmd.Process.Kill()
	}

	pm.UnregisterProcess(pid)
	return nil
}

func (pm *ProcessManager) Cleanup() {
	pm.processes.Range(func(key, value interface{}) bool {
		if pid, ok := key.(int); ok {
			pm.KillProcess(pid)
		}
		return true
	})
}

func findXrayExecutable() string {
	paths := []string{"./xray.exe", "xray.exe", "xray", "./xray", "/usr/local/bin/xray", "/usr/bin/xray"}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
	}

	return "./xray.exe"
}

type ConfigResult struct {
	Config       WorkingConfig `json:"config"`
	QualityTests []TestResult  `json:"quality_tests"`
	FinalScore   float64       `json:"final_score"`
	Category     QualityScore  `json:"category"`
	AvgLatency   float64       `json:"avg_latency"`
	SuccessRate  float64       `json:"success_rate"`
	Stability    float64       `json:"stability"`
	Speed        float64       `json:"speed_mbps"`
	TestTime     time.Time     `json:"test_time"`
}

type WorkingConfig struct {
	Protocol   string  `json:"protocol"`
	Server     string  `json:"server"`
	Port       int     `json:"port"`
	Method     string  `json:"method,omitempty"`
	Password   string  `json:"password,omitempty"`
	UUID       string  `json:"uuid,omitempty"`
	AlterID    int     `json:"alterId,omitempty"`
	Cipher     string  `json:"cipher,omitempty"`
	Network    string  `json:"network"`
	TLS        string  `json:"tls"`
	Path       string  `json:"path,omitempty"`
	Host       string  `json:"host,omitempty"`
	SNI        string  `json:"sni,omitempty"`
	Flow       string  `json:"flow,omitempty"`
	Encryption string  `json:"encryption,omitempty"`
	Remarks    string  `json:"remarks"`
	ExternalIP string  `json:"external_ip"`
	TestTime   float64 `json:"test_time"`
}

func (wc *WorkingConfig) Validate() error {
	if wc.Server == "" {
		return fmt.Errorf("server is required")
	}
	if wc.Port <= 0 || wc.Port > 65535 {
		return fmt.Errorf("invalid port: %d", wc.Port)
	}
	if wc.Protocol == "" {
		return fmt.Errorf("protocol is required")
	}

	switch wc.Protocol {
	case "shadowsocks":
		if wc.Method == "" || wc.Password == "" {
			return fmt.Errorf("method and password required for shadowsocks")
		}
	case "vmess":
		if wc.UUID == "" {
			return fmt.Errorf("UUID required for vmess")
		}
	case "vless":
		if wc.UUID == "" {
			return fmt.Errorf("UUID required for vless")
		}
	default:
		return fmt.Errorf("unsupported protocol: %s", wc.Protocol)
	}

	return nil
}

type TestResult struct {
	Site         string  `json:"site"`
	Success      bool    `json:"success"`
	Latency      float64 `json:"latency_ms"`
	DownloadTime float64 `json:"download_time_ms"`
	ContentSize  int64   `json:"content_size_bytes"`
	StatusCode   int     `json:"status_code"`
	ErrorMsg     string  `json:"error_message,omitempty"`
}

type QualityTester struct {
	config         *Config
	portManager    *PortManager
	processManager *ProcessManager
	testSites      []TestSite
	ctx            context.Context
	cancel         context.CancelFunc
}

type TestSite struct {
	Name        string
	URL         string
	ExpectedStr string
	Category    string
}

func NewQualityTester(config *Config) *QualityTester {
	if config == nil {
		config = DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	testSites := []TestSite{
		{"Twitter", "https://twitter.com", "twitter", "filtered_primary"},
		{"YouTube", "https://www.youtube.com", "watch", "filtered_primary"},
		{"Instagram", "https://www.instagram.com", "instagram", "filtered_primary"},
		{"Discord", "https://discord.com", "discord", "filtered_primary"},
		{"Telegram Web", "https://web.telegram.org", "telegram", "filtered_secondary"},
	}

	return &QualityTester{
		config:         config,
		portManager:    NewPortManager(ctx, config.PortStart, config.PortEnd),
		processManager: NewProcessManager(ctx),
		testSites:      testSites,
		ctx:            ctx,
		cancel:         cancel,
	}
}

func (qt *QualityTester) LoadWorkingConfigs(filePath string) ([]WorkingConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var configs []WorkingConfig
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var config WorkingConfig
		if err := json.Unmarshal([]byte(line), &config); err != nil {
			log.Printf("Warning: skipping invalid config at line %d: %v", lineNum, err)
			continue
		}

		if err := config.Validate(); err != nil {
			log.Printf("Warning: skipping invalid config at line %d: %v", lineNum, err)
			continue
		}

		configs = append(configs, config)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	return configs, nil
}

func (qt *QualityTester) TestConfigQuality(config *WorkingConfig) (*ConfigResult, error) {
	select {
	case <-qt.ctx.Done():
		return nil, qt.ctx.Err()
	default:
	}

	proxyPort, err := qt.portManager.GetAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("no available port: %w", err)
	}
	defer qt.portManager.ReleasePort(proxyPort)

	xrayConfig, err := qt.generateXrayConfig(config, proxyPort)
	if err != nil {
		return nil, fmt.Errorf("failed to generate config: %w", err)
	}

	configFile, err := qt.writeConfigToTempFile(xrayConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to write config file: %w", err)
	}
	defer os.Remove(configFile)

	process, err := qt.startXrayProcess(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to start Xray: %w", err)
	}
	defer func() {
		if process != nil && process.Process != nil {
			qt.processManager.KillProcess(process.Process.Pid)
		}
	}()

	select {
	case <-time.After(XrayStartupTimeout):
	case <-qt.ctx.Done():
		return nil, qt.ctx.Err()
	}

	if process.ProcessState != nil && process.ProcessState.Exited() {
		return nil, fmt.Errorf("xray process exited")
	}

	results := qt.runQualityTests(proxyPort)

	result := &ConfigResult{
		Config:       *config,
		QualityTests: results,
		TestTime:     time.Now(),
	}

	qt.calculateQualityMetrics(result)

	log.Printf("Config %s:%d completed - Score: %.1f | Success: %.1f%% | Latency: %.0fms | Tests: %d/%d passed",
		config.Server, config.Port, result.FinalScore, result.SuccessRate, result.AvgLatency,
		qt.countSuccessfulTests(result.QualityTests), len(result.QualityTests))

	return result, nil
}

func (qt *QualityTester) countSuccessfulTests(tests []TestResult) int {
	count := 0
	for _, test := range tests {
		if test.Success {
			count++
		}
	}
	return count
}

func (qt *QualityTester) runQualityTests(proxyPort int) []TestResult {
	var results []TestResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	completed := 0
	totalTests := len(qt.testSites)

	semaphore := make(chan struct{}, qt.config.Concurrent)

	log.Printf("Starting quality tests for %d sites via port %d...", totalTests, proxyPort)

	for _, site := range qt.testSites {
		wg.Add(1)
		go func(testSite TestSite) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
			case <-qt.ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			result := qt.testSingleSite(proxyPort, testSite)

			mu.Lock()
			results = append(results, result)
			completed++
			log.Printf("Progress: %d/%d tests completed (%.1f%%) - Last: %s",
				completed, totalTests, float64(completed)/float64(totalTests)*100, testSite.Name)
			mu.Unlock()
		}(site)
	}

	wg.Wait()
	log.Printf("All quality tests completed for port %d", proxyPort)
	return results
}

func (qt *QualityTester) testSingleSite(proxyPort int, site TestSite) TestResult {
	result := TestResult{
		Site: site.Name,
	}

	if qt.config.TestCritical && qt.isCriticalSite(site.Name) {
		return qt.testSiteStability(proxyPort, site)
	}

	for attempt := 0; attempt <= qt.config.MaxRetries; attempt++ {
		select {
		case <-qt.ctx.Done():
			result.Success = false
			result.ErrorMsg = "context cancelled"
			return result
		default:
		}

		success, latency, downloadTime, contentSize, statusCode, err := qt.performRequest(proxyPort, site.URL, site.ExpectedStr)

		if success {
			result.Success = true
			result.Latency = latency
			result.DownloadTime = downloadTime
			result.ContentSize = contentSize
			result.StatusCode = statusCode
			log.Printf("SUCCESS %s via port %d: %.0fms (HTTP %d, %d bytes)",
				site.Name, proxyPort, latency, statusCode, contentSize)
			break
		}

		if attempt == qt.config.MaxRetries {
			result.Success = false
			if err != nil {
				result.ErrorMsg = err.Error()
			}
			result.StatusCode = statusCode
			if statusCode > 0 {
				log.Printf("FAILED %s via port %d: (HTTP %d) - %v",
					site.Name, proxyPort, statusCode, err)
			} else {
				log.Printf("FAILED %s via port %d: %v",
					site.Name, proxyPort, err)
			}
		}

		if attempt < qt.config.MaxRetries {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}

	return result
}

func (qt *QualityTester) isCriticalSite(siteName string) bool {
	criticalSites := []string{"Twitter", "Instagram", "YouTube", "Discord"}
	for _, critical := range criticalSites {
		if siteName == critical {
			return true
		}
	}
	return false
}

func (qt *QualityTester) testSiteStability(proxyPort int, site TestSite) TestResult {
	result := TestResult{
		Site: site.Name,
	}

	stabilityTests := []time.Duration{
		0 * time.Second,
		2 * time.Second,
		5 * time.Second,
		8 * time.Second,
	}

	successCount := 0
	totalLatency := 0.0
	totalDownloadTime := 0.0
	totalContentSize := int64(0)
	lastStatusCode := 0

	log.Printf("Testing stability for %s via port %d...", site.Name, proxyPort)

	for i, delay := range stabilityTests {
		select {
		case <-qt.ctx.Done():
			result.Success = false
			result.ErrorMsg = "context cancelled"
			return result
		default:
		}

		if i > 0 {
			time.Sleep(delay - stabilityTests[i-1])
		}

		success, latency, downloadTime, contentSize, statusCode, err := qt.performRequest(proxyPort, site.URL, site.ExpectedStr)

		if success {
			successCount++
			totalLatency += latency
			totalDownloadTime += downloadTime
			totalContentSize += contentSize
			lastStatusCode = statusCode
			log.Printf("  SUCCESS Attempt %d/%d: %.0fms", i+1, len(stabilityTests), latency)
		} else {
			log.Printf("  FAILED Attempt %d/%d: %v", i+1, len(stabilityTests), err)
		}
	}

	stabilityRate := float64(successCount) / float64(len(stabilityTests))

	if stabilityRate >= StabilityThreshold {
		result.Success = true
		if successCount > 0 {
			result.Latency = totalLatency / float64(successCount)
			result.DownloadTime = totalDownloadTime / float64(successCount)
			result.ContentSize = totalContentSize / int64(successCount)
		}
		result.StatusCode = lastStatusCode

		log.Printf("SUCCESS %s via port %d: STABLE (%.1f%% success, avg %.0fms)",
			site.Name, proxyPort, stabilityRate*100, result.Latency)
	} else {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("Unstable connection: only %.1f%% success rate", stabilityRate*100)

		log.Printf("FAILED %s via port %d: UNSTABLE (%.1f%% success)",
			site.Name, proxyPort, stabilityRate*100)
	}

	return result
}

func (qt *QualityTester) performRequest(proxyPort int, targetURL, expectedContent string) (bool, float64, float64, int64, int, error) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return false, 0, 0, 0, 0, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:     true,
		DisableCompression:    false,
		MaxIdleConns:          5,
		IdleConnTimeout:       15 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   qt.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	ctx, cancel := context.WithTimeout(qt.ctx, qt.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false, 0, 0, 0, 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	connectTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, 0, 0, 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	latency := time.Since(connectTime).Seconds() * 1000

	downloadStart := time.Now()
	body, err := io.ReadAll(resp.Body)
	downloadTime := time.Since(downloadStart).Seconds() * 1000

	if err != nil {
		return false, latency, 0, 0, resp.StatusCode, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, latency, downloadTime, int64(len(body)), resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if expectedContent != "" && !qt.validateContent(string(body), expectedContent) {
		return false, latency, downloadTime, int64(len(body)), resp.StatusCode, fmt.Errorf("expected content not found or content blocked")
	}

	return true, latency, downloadTime, int64(len(body)), resp.StatusCode, nil
}

func (qt *QualityTester) validateContent(body, expectedContent string) bool {
	bodyLower := strings.ToLower(body)
	expectedLower := strings.ToLower(expectedContent)

	if expectedContent == "origin" {
		return strings.Contains(bodyLower, expectedLower)
	}

	if len(body) < 500 {
		return false
	}

	blockedIndicators := []string{"access denied", "403 forbidden", "blocked", "not available"}
	for _, indicator := range blockedIndicators {
		if strings.Contains(bodyLower, indicator) {
			return false
		}
	}

	return true
}

func (qt *QualityTester) calculateQualityMetrics(result *ConfigResult) {
	var latencies []float64
	var downloadTimes []float64
	var contentSizes []int64
	successCount := 0

	for _, test := range result.QualityTests {
		if test.Success {
			successCount++
			latencies = append(latencies, test.Latency)
			downloadTimes = append(downloadTimes, test.DownloadTime)
			contentSizes = append(contentSizes, test.ContentSize)
		}
	}

	totalTests := len(result.QualityTests)
	if totalTests == 0 {
		return
	}

	result.SuccessRate = float64(successCount) / float64(totalTests) * 100

	if len(latencies) > 0 {
		sum := 0.0
		for _, lat := range latencies {
			sum += lat
		}
		result.AvgLatency = sum / float64(len(latencies))

		variance := 0.0
		for _, lat := range latencies {
			variance += math.Pow(lat-result.AvgLatency, 2)
		}
		if len(latencies) > 1 {
			stdDev := math.Sqrt(variance / float64(len(latencies)-1))
			if result.AvgLatency > 0 {
				result.Stability = math.Max(0, 100-(stdDev/result.AvgLatency*100))
			} else {
				result.Stability = 0
			}
		} else {
			result.Stability = 100
		}
	}

	if len(downloadTimes) > 0 && len(contentSizes) > 0 {
		totalBytes := int64(0)
		totalTime := 0.0
		for i, size := range contentSizes {
			totalBytes += size
			totalTime += downloadTimes[i]
		}
		if totalTime > 0 {
			bytesPerMs := float64(totalBytes) / totalTime
			result.Speed = (bytesPerMs * 1000 * 8) / (1024 * 1024)
		}
	}

	result.FinalScore = qt.calculateFinalScore(result)
}

func (qt *QualityTester) calculateFinalScore(result *ConfigResult) float64 {
	if result.SuccessRate == 0 {
		return 0
	}

	iranFilteredScore := qt.calculateIranFilteredScore(result.QualityTests)

	filteredSitesWeight := 0.50
	latencyWeight := 0.25
	stabilityWeight := 0.15
	speedWeight := 0.10

	latencyScore := 100.0
	if result.AvgLatency > 0 {
		if result.AvgLatency <= 1000 {
			latencyScore = 100
		} else if result.AvgLatency >= MaxLatencyMs {
			latencyScore = 0
		} else {
			latencyScore = 100 - ((result.AvgLatency-1000)/(MaxLatencyMs-1000))*100
		}
	}

	stabilityScore := result.Stability
	speedScore := math.Min(100, result.Speed*10)

	finalScore := (iranFilteredScore*filteredSitesWeight +
		latencyScore*latencyWeight +
		stabilityScore*stabilityWeight +
		speedScore*speedWeight)

	bonusScore := qt.calculateBonusScore(result.QualityTests)
	finalScore = math.Min(100, finalScore+bonusScore)

	return math.Round(finalScore*100) / 100
}

func (qt *QualityTester) calculateIranFilteredScore(tests []TestResult) float64 {
	primaryFilteredSites := []string{"Twitter", "YouTube", "Instagram", "Discord"}
	primarySuccessCount := 0

	for _, test := range tests {
		if test.Success {
			for _, site := range primaryFilteredSites {
				if test.Site == site {
					primarySuccessCount++
					break
				}
			}
		}
	}

	if len(primaryFilteredSites) == 0 {
		return 0
	}

	return float64(primarySuccessCount) / float64(len(primaryFilteredSites)) * 100
}

func (qt *QualityTester) calculateBonusScore(tests []TestResult) float64 {
	criticalSites := []string{"Twitter", "Instagram", "YouTube", "Discord"}
	successCount := 0

	for _, test := range tests {
		if test.Success && test.Latency < 800 {
			for _, site := range criticalSites {
				if test.Site == site {
					successCount++
					break
				}
			}
		}
	}

	if successCount == len(criticalSites) {
		return 10.0
	} else if successCount >= len(criticalSites)*3/4 {
		return 5.0
	}

	return 0
}

func (qt *QualityTester) categorizeByRank(results []ConfigResult) {
	if len(results) == 0 {
		return
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].FinalScore > results[j].FinalScore
	})

	totalCount := len(results)
	excellentCount := int(math.Max(1, float64(totalCount)*0.10))
	veryGoodCount := int(float64(totalCount) * 0.20)
	goodCount := int(float64(totalCount) * 0.30)
	fairCount := int(float64(totalCount) * 0.25)

	index := 0
	for i := 0; i < excellentCount && index < totalCount; i++ {
		results[index].Category = ScoreExcellent
		index++
	}
	for i := 0; i < veryGoodCount && index < totalCount; i++ {
		results[index].Category = ScoreVeryGood
		index++
	}
	for i := 0; i < goodCount && index < totalCount; i++ {
		results[index].Category = ScoreGood
		index++
	}
	for i := 0; i < fairCount && index < totalCount; i++ {
		results[index].Category = ScoreFair
		index++
	}
	for index < totalCount {
		results[index].Category = ScorePoor
		index++
	}

	log.Printf("Rank-based categorization completed:")
	log.Printf("   Excellent: %d configs (%.1f%%)", excellentCount, float64(excellentCount)/float64(totalCount)*100)
	log.Printf("   Very Good: %d configs (%.1f%%)", veryGoodCount, float64(veryGoodCount)/float64(totalCount)*100)
	log.Printf("   Good: %d configs (%.1f%%)", goodCount, float64(goodCount)/float64(totalCount)*100)
	log.Printf("   Fair: %d configs (%.1f%%)", fairCount, float64(fairCount)/float64(totalCount)*100)
	log.Printf("   Poor: %d configs (%.1f%%)", totalCount-excellentCount-veryGoodCount-goodCount-fairCount, float64(totalCount-excellentCount-veryGoodCount-goodCount-fairCount)/float64(totalCount)*100)
}

func (qt *QualityTester) generateXrayConfig(config *WorkingConfig, listenPort int) (map[string]interface{}, error) {
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
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": config.Protocol,
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
	case "shadowsocks":
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

	case "vmess":
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

	case "vless":
		outbound["settings"] = map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": config.Server,
					"port":    config.Port,
					"users": []map[string]interface{}{
						{
							"id":         config.UUID,
							"flow":       config.Flow,
							"encryption": config.Encryption,
							"level":      0,
						},
					},
				},
			},
		}

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
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

		if config.TLS == "tls" {
			streamSettings["tlsSettings"] = tlsSettings
		} else if config.TLS == "reality" {
			streamSettings["realitySettings"] = tlsSettings
		}
	}

	return xrayConfig, nil
}

func (qt *QualityTester) writeConfigToTempFile(config map[string]interface{}) (string, error) {
	tmpFile, err := os.CreateTemp("", "xray-quality-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write config: %w", err)
	}

	return tmpFile.Name(), nil
}

func (qt *QualityTester) startXrayProcess(configFile string) (*exec.Cmd, error) {
	ctx, cancel := context.WithTimeout(qt.ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, qt.config.XrayPath, "run", "-config", configFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start xray process: %w", err)
	}

	qt.processManager.RegisterProcess(cmd.Process.Pid, cmd)
	return cmd, nil
}

func (qt *QualityTester) SaveResults(results []ConfigResult) error {
	if err := os.MkdirAll(qt.config.OutputPath, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	qt.categorizeByRank(results)

	categories := map[QualityScore][]ConfigResult{
		ScoreExcellent: {},
		ScoreVeryGood:  {},
		ScoreGood:      {},
		ScoreFair:      {},
		ScorePoor:      {},
	}

	for _, result := range results {
		categories[result.Category] = append(categories[result.Category], result)
	}

	categoryNames := map[QualityScore]string{
		ScoreExcellent: "excellent",
		ScoreVeryGood:  "very_good",
		ScoreGood:      "good",
		ScoreFair:      "fair",
		ScorePoor:      "poor",
	}

	for category, configs := range categories {
		if len(configs) > 0 {
			sort.Slice(configs, func(i, j int) bool {
				return configs[i].FinalScore > configs[j].FinalScore
			})
			if err := qt.saveCategory(categoryNames[category], configs); err != nil {
				return fmt.Errorf("failed to save %s category: %w", categoryNames[category], err)
			}
		}
	}

	return qt.saveSummary(results)
}

func (qt *QualityTester) saveCategory(category string, results []ConfigResult) error {
	fileName := fmt.Sprintf("%s/%s_configs.txt", qt.config.OutputPath, category)
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create category file: %w", err)
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString(fmt.Sprintf("# %s Quality Proxy Configurations\n", strings.ToTitle(category)))
	file.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
	file.WriteString(fmt.Sprintf("# Total configurations: %d\n\n", len(results)))

	for _, result := range results {
		configURL := qt.createConfigURL(&result)
		file.WriteString(fmt.Sprintf("%s\n", configURL))
	}

	return nil
}

func (qt *QualityTester) saveSummary(results []ConfigResult) error {
	fileName := fmt.Sprintf("%s/summary.txt", qt.config.OutputPath)
	file, err := os.Create(fileName)
	if err != nil {
		return fmt.Errorf("failed to create summary file: %w", err)
	}
	defer file.Close()

	categoryCount := map[QualityScore]int{
		ScoreExcellent: 0,
		ScoreVeryGood:  0,
		ScoreGood:      0,
		ScoreFair:      0,
		ScorePoor:      0,
	}

	totalScore := 0.0
	for _, result := range results {
		totalScore += result.FinalScore
		categoryCount[result.Category]++
	}

	avgScore := 0.0
	if len(results) > 0 {
		avgScore = totalScore / float64(len(results))
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString("# Proxy Quality Test Summary\n")
	file.WriteString(fmt.Sprintf("# Generated at: %s\n\n", timestamp))
	file.WriteString(fmt.Sprintf("Total configurations tested: %d\n", len(results)))
	file.WriteString(fmt.Sprintf("Average quality score: %.2f\n\n", avgScore))
	file.WriteString("Quality Distribution (Rank-Based):\n")
	file.WriteString(fmt.Sprintf("  Excellent (Top 10%% Best): %d (%.1f%%)\n",
		categoryCount[ScoreExcellent], float64(categoryCount[ScoreExcellent])/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Very Good (Next 20%% Best): %d (%.1f%%)\n",
		categoryCount[ScoreVeryGood], float64(categoryCount[ScoreVeryGood])/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Good (Next 30%% Best): %d (%.1f%%)\n",
		categoryCount[ScoreGood], float64(categoryCount[ScoreGood])/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Fair (Next 25%% Best): %d (%.1f%%)\n",
		categoryCount[ScoreFair], float64(categoryCount[ScoreFair])/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Poor (Bottom 15%%): %d (%.1f%%)\n",
		categoryCount[ScorePoor], float64(categoryCount[ScorePoor])/float64(len(results))*100))

	return nil
}

func (qt *QualityTester) createConfigURL(result *ConfigResult) string {
	config := &result.Config

	switch config.Protocol {
	case "shadowsocks":
		auth := fmt.Sprintf("%s:%s", config.Method, config.Password)
		authB64 := base64.StdEncoding.EncodeToString([]byte(auth))
		remarks := url.QueryEscape(config.Remarks)
		if remarks == "" {
			remarks = fmt.Sprintf("SS-%s", config.Server)
		}
		return fmt.Sprintf("ss://%s@%s:%d#%s", authB64, config.Server, config.Port, remarks)

	case "vmess":
		vmessConfig := map[string]interface{}{
			"v":    "2",
			"ps":   config.Remarks,
			"add":  config.Server,
			"port": strconv.Itoa(config.Port),
			"id":   config.UUID,
			"aid":  strconv.Itoa(config.AlterID),
			"scy":  config.Cipher,
			"net":  config.Network,
			"type": "none",
			"host": config.Host,
			"path": config.Path,
			"tls":  config.TLS,
			"sni":  config.SNI,
		}
		if vmessConfig["ps"] == "" {
			vmessConfig["ps"] = fmt.Sprintf("VMess-%s", config.Server)
		}

		jsonBytes, _ := json.Marshal(vmessConfig)
		vmessB64 := base64.StdEncoding.EncodeToString(jsonBytes)
		return fmt.Sprintf("vmess://%s", vmessB64)

	case "vless":
		params := url.Values{}
		if config.Encryption != "" && config.Encryption != "none" {
			params.Add("encryption", config.Encryption)
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

func (qt *QualityTester) RunQualityTests(configFile string) error {
	log.Println("Loading working configurations...")
	configs, err := qt.LoadWorkingConfigs(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configs: %w", err)
	}

	if qt.config.MaxConfigs > 0 && len(configs) > qt.config.MaxConfigs {
		configs = configs[:qt.config.MaxConfigs]
	}

	log.Printf("Testing quality for %d configurations with %d test sites each...", len(configs), len(qt.testSites))

	var results []ConfigResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, qt.config.Concurrent)
	processed := 0
	totalConfigs := len(configs)

	for _, config := range configs {
		wg.Add(1)
		go func(cfg WorkingConfig) {
			defer wg.Done()

			select {
			case semaphore <- struct{}{}:
			case <-qt.ctx.Done():
				return
			}
			defer func() { <-semaphore }()

			result, err := qt.TestConfigQuality(&cfg)
			if err != nil {
				log.Printf("Failed to test config %s:%d - %v", cfg.Server, cfg.Port, err)
				mu.Lock()
				processed++
				log.Printf("Overall Progress: %d/%d configs tested (%.1f%%) - Failed: %s:%d",
					processed, totalConfigs, float64(processed)/float64(totalConfigs)*100, cfg.Server, cfg.Port)
				mu.Unlock()
				return
			}

			mu.Lock()
			results = append(results, *result)
			processed++
			log.Printf("Overall Progress: %d/%d configs tested (%.1f%%) - Score: %.1f | Success: %.1f%% | Latency: %.0fms",
				processed, totalConfigs, float64(processed)/float64(totalConfigs)*100,
				result.FinalScore, result.SuccessRate, result.AvgLatency)
			mu.Unlock()

			log.Printf("Config %s:%d completed - Score: %.1f, Success: %.1f%%, Latency: %.0fms",
				cfg.Server, cfg.Port, result.FinalScore, result.SuccessRate, result.AvgLatency)
		}(config)
	}

	wg.Wait()

	if len(results) == 0 {
		return fmt.Errorf("no valid results to save")
	}

	log.Printf("Quality testing completed. Saving results...")
	if err := qt.SaveResults(results); err != nil {
		return fmt.Errorf("failed to save results: %w", err)
	}

	qt.printQualitySummary(results)
	return nil
}

func (qt *QualityTester) printQualitySummary(results []ConfigResult) {
	categoryCount := map[QualityScore]int{
		ScoreExcellent: 0,
		ScoreVeryGood:  0,
		ScoreGood:      0,
		ScoreFair:      0,
		ScorePoor:      0,
	}

	totalScore := 0.0
	for _, result := range results {
		totalScore += result.FinalScore
		categoryCount[result.Category]++
	}

	avgScore := totalScore / float64(len(results))

	log.Println("=" + strings.Repeat("=", 60))
	log.Println("QUALITY TESTING SUMMARY")
	log.Println("=" + strings.Repeat("=", 60))
	log.Printf("Total configurations tested: %d", len(results))
	log.Printf("Average quality score: %.1f", avgScore)
	log.Println()
	log.Printf("Excellent (Top 10%% Best): %d (%.1f%%)",
		categoryCount[ScoreExcellent], float64(categoryCount[ScoreExcellent])/float64(len(results))*100)
	log.Printf("Very Good (Next 20%% Best): %d (%.1f%%)",
		categoryCount[ScoreVeryGood], float64(categoryCount[ScoreVeryGood])/float64(len(results))*100)
	log.Printf("Good (Next 30%% Best): %d (%.1f%%)",
		categoryCount[ScoreGood], float64(categoryCount[ScoreGood])/float64(len(results))*100)
	log.Printf("Fair (Next 25%% Best): %d (%.1f%%)",
		categoryCount[ScoreFair], float64(categoryCount[ScoreFair])/float64(len(results))*100)
	log.Printf("Poor (Others): %d (%.1f%%)",
		categoryCount[ScorePoor], float64(categoryCount[ScorePoor])/float64(len(results))*100)
	log.Println()
	log.Println("Results saved to:")
	log.Printf("  %s/excellent_configs.txt", qt.config.OutputPath)
	log.Printf("  %s/very_good_configs.txt", qt.config.OutputPath)
	log.Printf("  %s/good_configs.txt", qt.config.OutputPath)
	log.Printf("  %s/fair_configs.txt", qt.config.OutputPath)
	log.Printf("  %s/poor_configs.txt", qt.config.OutputPath)
	log.Printf("  %s/summary.txt", qt.config.OutputPath)
	log.Println("=" + strings.Repeat("=", 60))
}

func (qt *QualityTester) Cleanup() {
	if qt.cancel != nil {
		qt.cancel()
	}
	qt.processManager.Cleanup()
}

func setupSignalHandler(tester *QualityTester) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Received interrupt signal, cleaning up...")
		tester.Cleanup()
		os.Exit(1)
	}()
}

func main() {
	config := DefaultConfig()

	if xrayPath := os.Getenv("XRAY_PATH"); xrayPath != "" {
		config.XrayPath = xrayPath
	}

	if maxConfigsEnv := os.Getenv("MAX_CONFIGS"); maxConfigsEnv != "" {
		if maxConfigs, err := strconv.Atoi(maxConfigsEnv); err == nil && maxConfigs > 0 {
			config.MaxConfigs = maxConfigs
		}
	}

	if concurrentEnv := os.Getenv("CONCURRENT"); concurrentEnv != "" {
		if concurrent, err := strconv.Atoi(concurrentEnv); err == nil && concurrent > 0 {
			config.Concurrent = concurrent
		}
	}

	if outputPathEnv := os.Getenv("OUTPUT_PATH"); outputPathEnv != "" {
		config.OutputPath = outputPathEnv
	}

	configFile := "data/working_json/working_all_configs.txt"
	if configFileEnv := os.Getenv("CONFIG_FILE"); configFileEnv != "" {
		configFile = configFileEnv
	}

	tester := NewQualityTester(config)
	defer tester.Cleanup()

	setupSignalHandler(tester)

	log.Printf("Starting quality tester with config: MaxConfigs=%d, Concurrent=%d, Timeout=%v",
		config.MaxConfigs, config.Concurrent, config.Timeout)

	if err := tester.RunQualityTests(configFile); err != nil {
		log.Fatalf("Quality testing failed: %v", err)
	}

	log.Println("Quality testing completed successfully")
}
