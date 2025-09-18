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
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

type SpeedCategory int

const (
	SpeedFast   SpeedCategory = 1
	SpeedMedium SpeedCategory = 2
	SpeedSlow   SpeedCategory = 3
)

type SpeedTestResult struct {
	Config       WorkingConfig `json:"config"`
	DownloadSpeed float64      `json:"download_speed_mbps"`
	TestTime     float64       `json:"test_time_seconds"`
	Success      bool         `json:"success"`
	ErrorMessage string       `json:"error_message,omitempty"`
	Category     SpeedCategory `json:"category"`
	TestURL      string       `json:"test_url"`
	FileSize     int64        `json:"file_size_bytes"`
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

type SpeedTestService struct {
	Name        string
	URL         string
	FileSize    int64
	Description string
	Priority    int
}

type PortManager struct {
	startPort      int
	endPort        int
	availablePorts chan int
	usedPorts      sync.Map
	mu             sync.Mutex
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
		pm.usedPorts.Store(port, time.Now())
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

	for i := 0; i < 30; i++ {
		port := pm.startPort + (i*19)%(pm.endPort-pm.startPort+1)
		if _, used := pm.usedPorts.Load(port); !used && pm.isPortAvailable(port) {
			pm.usedPorts.Store(port, time.Now())
			return port, nil
		}
	}
	return 0, fmt.Errorf("no available ports")
}

func (pm *PortManager) ReleasePort(port int) {
	pm.usedPorts.Delete(port)
	go func() {
		select {
		case <-time.After(50 * time.Millisecond):
		case <-pm.ctx.Done():
			return
		}
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
	pm := &ProcessManager{ctx: ctx}
	go pm.cleanupExpiredProcesses()
	return pm
}

func (pm *ProcessManager) cleanupExpiredProcesses() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pm.processes.Range(func(key, value interface{}) bool {
				if cmd, ok := value.(*exec.Cmd); ok {
					if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
						pm.processes.Delete(key)
					}
				}
				return true
			})
		case <-pm.ctx.Done():
			return
		}
	}
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
		pm.UnregisterProcess(pid)
		return fmt.Errorf("invalid process")
	}

	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		pm.UnregisterProcess(pid)
		return nil
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err == nil {
		done := make(chan error, 1)
		go func() {
			done <- cmd.Wait()
		}()

		select {
		case <-done:
		case <-time.After(1500 * time.Millisecond):
			cmd.Process.Kill()
			<-done
		}
	} else {
		cmd.Process.Kill()
		cmd.Wait()
	}

	pm.UnregisterProcess(pid)
	return nil
}

func (pm *ProcessManager) Cleanup() {
	var wg sync.WaitGroup
	pm.processes.Range(func(key, value interface{}) bool {
		if pid, ok := key.(int); ok {
			wg.Add(1)
			go func(p int) {
				defer wg.Done()
				pm.KillProcess(p)
			}(pid)
		}
		return true
	})

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

type SpeedTester struct {
	xrayPath       string
	portManager    *PortManager
	processManager *ProcessManager
	testServices   []SpeedTestService
	maxWorkers     int
	timeout        time.Duration
	concurrent     int
	ctx            context.Context
	cancel         context.CancelFunc
	baseDir        string
}

func NewSpeedTester(ctx context.Context, xrayPath string, maxWorkers int, concurrent int) *SpeedTester {
	ctx, cancel := context.WithCancel(ctx)

	if xrayPath == "" {
		xrayPath = findXrayExecutable()
	}

	testServices := []SpeedTestService{
		{
			Name:        "Cloudflare",
			URL:         "https://speed.cloudflare.com/__down?bytes=5242880",
			FileSize:    5242880,
			Description: "Cloudflare 5MB test",
			Priority:    1,
		},
		{
			Name:        "GitHub",
			URL:         "https://github.com/microsoft/vscode/archive/refs/heads/main.zip",
			FileSize:    20971520,
			Description: "GitHub archive test",
			Priority:    2,
		},
		{
			Name:        "Fast",
			URL:         "https://fast.com/app-5mb.png",
			FileSize:    5242880,
			Description: "Fast.com 5MB test",
			Priority:    3,
		},
	}

	sort.Slice(testServices, func(i, j int) bool {
		return testServices[i].Priority < testServices[j].Priority
	})

	baseDir, _ := os.Getwd()

	return &SpeedTester{
		xrayPath:       xrayPath,
		portManager:    NewPortManager(ctx, 32000, 34000),
		processManager: NewProcessManager(ctx),
		testServices:   testServices,
		maxWorkers:     maxWorkers,
		timeout:        90 * time.Second,
		concurrent:     concurrent,
		ctx:            ctx,
		cancel:         cancel,
		baseDir:        baseDir,
	}
}

func findXrayExecutable() string {
	paths := []string{
		"./xray",
		"./xray.exe",
		"xray",
		"xray.exe",
		"/usr/local/bin/xray",
		"/usr/bin/xray",
		"/opt/xray/xray",
	}

	for _, path := range paths {
		if absPath, err := exec.LookPath(path); err == nil {
			return absPath
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	if runtime.GOOS == "windows" {
		return "./xray.exe"
	}
	return "./xray"
}

func (st *SpeedTester) LoadWorkingConfigs(filePath string) ([]WorkingConfig, error) {
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(st.baseDir, filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file: %w", err)
	}
	defer file.Close()

	var configs []WorkingConfig
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 512*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var config WorkingConfig
		if err := json.Unmarshal([]byte(line), &config); err != nil {
			continue
		}

		if config.Server == "" || config.Port == 0 || config.Protocol == "" {
			continue
		}

		configs = append(configs, config)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	return configs, nil
}

func (st *SpeedTester) TestConfigSpeed(ctx context.Context, config *WorkingConfig) (*SpeedTestResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	proxyPort, err := st.portManager.GetAvailablePort()
	if err != nil {
		return nil, fmt.Errorf("failed to get available port: %w", err)
	}
	defer st.portManager.ReleasePort(proxyPort)

	result := &SpeedTestResult{Config: *config}

	xrayConfig, err := st.generateXrayConfig(config, proxyPort)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("config generation failed: %v", err)
		return result, nil
	}

	configFile, err := st.writeConfigToTempFile(xrayConfig)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("temp file creation failed: %v", err)
		return result, nil
	}
	defer os.Remove(configFile)

	processCtx, processCancel := context.WithTimeout(ctx, st.timeout)
	defer processCancel()

	process, err := st.startXrayProcess(processCtx, configFile)
	if err != nil {
		result.Success = false
		result.ErrorMessage = fmt.Sprintf("process start failed: %v", err)
		return result, nil
	}

	defer func() {
		if process != nil && process.Process != nil {
			st.processManager.KillProcess(process.Process.Pid)
		}
	}()

	select {
	case <-time.After(1500 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if process.ProcessState != nil && process.ProcessState.Exited() {
		result.Success = false
		result.ErrorMessage = "xray process exited unexpectedly"
		return result, nil
	}

	speed, testTime, testURL, fileSize, err := st.performSpeedTest(ctx, proxyPort)
	if err != nil {
		result.Success = false
		result.ErrorMessage = err.Error()
		result.TestTime = testTime
	} else {
		result.Success = true
		result.DownloadSpeed = speed
		result.TestTime = testTime
		result.TestURL = testURL
		result.FileSize = fileSize
	}

	return result, nil
}

func (st *SpeedTester) performSpeedTest(ctx context.Context, proxyPort int) (float64, float64, string, int64, error) {
	var bestSpeed float64
	var bestTime float64
	var bestURL string
	var bestFileSize int64
	var lastErr error

	for _, service := range st.testServices {
		select {
		case <-ctx.Done():
			return 0, 0, "", 0, ctx.Err()
		default:
		}

		speed, testTime, fileSize, err := st.testSingleService(ctx, proxyPort, service)
		if err != nil {
			lastErr = err
			continue
		}

		if speed > bestSpeed {
			bestSpeed = speed
			bestTime = testTime
			bestURL = service.URL
			bestFileSize = fileSize
		}

		if speed > 8 {
			break
		}
	}

	if bestSpeed == 0 {
		if lastErr != nil {
			return 0, 0, "", 0, lastErr
		}
		return 0, 0, "", 0, fmt.Errorf("all speed tests failed")
	}

	return bestSpeed, bestTime, bestURL, bestFileSize, nil
}

func (st *SpeedTester) testSingleService(ctx context.Context, proxyPort int, service SpeedTestService) (float64, float64, int64, error) {
	serviceCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("proxy dial failed: %w", err)
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:     true,
		DisableCompression:    true,
		MaxIdleConns:          1,
		IdleConnTimeout:       20 * time.Second,
		TLSHandshakeTimeout:   20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   45 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(serviceCtx, "GET", service.URL, nil)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("request creation failed: %w", err)
	}

	req.Header.Set("User-Agent", "SpeedTest/2.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "close")

	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, time.Since(startTime).Seconds(), 0, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, time.Since(startTime).Seconds(), 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	downloadStart := time.Now()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))

	downloadTime := time.Since(downloadStart).Seconds()
	totalTime := time.Since(startTime).Seconds()

	if err != nil {
		return 0, totalTime, 0, fmt.Errorf("download failed: %w", err)
	}

	bytesDownloaded := int64(len(body))
	if bytesDownloaded == 0 {
		return 0, totalTime, 0, fmt.Errorf("no data received")
	}

	if downloadTime <= 0.01 {
		downloadTime = totalTime * 0.8
	}

	speedMbps := (float64(bytesDownloaded) * 8) / (downloadTime * 1024 * 1024)

	if speedMbps > 500 {
		speedMbps = (float64(bytesDownloaded) * 8) / (totalTime * 1024 * 1024)
	}

	return speedMbps, totalTime, bytesDownloaded, nil
}

func (st *SpeedTester) generateXrayConfig(config *WorkingConfig, listenPort int) (map[string]interface{}, error) {
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
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": config.Protocol,
				"settings": map[string]interface{}{},
				"streamSettings": map[string]interface{}{
					"sockopt": map[string]interface{}{
						"tcpKeepAliveInterval": 60,
						"tcpNoDelay":          true,
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

		case "h2", "http":
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
			if config.Path != "" {
				grpcSettings["serviceName"] = config.Path
			}
			streamSettings["grpcSettings"] = grpcSettings
		}
	}

	if config.TLS != "" && config.TLS != "none" {
		streamSettings["security"] = config.TLS
		tlsSettings := map[string]interface{}{
			"allowInsecure": true,
		}

		serverName := config.SNI
		if serverName == "" && config.Host != "" {
			serverName = config.Host
		}

		if serverName != "" {
			tlsSettings["serverName"] = serverName
		}

		switch config.TLS {
		case "tls":
			streamSettings["tlsSettings"] = tlsSettings
		case "reality":
			streamSettings["realitySettings"] = tlsSettings
		case "xtls":
			streamSettings["xtlsSettings"] = tlsSettings
		}
	}

	return xrayConfig, nil
}

func (st *SpeedTester) writeConfigToTempFile(config map[string]interface{}) (string, error) {
	tmpFile, err := os.CreateTemp("", "xray-speed-*.json")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	encoder := json.NewEncoder(tmpFile)
	if err := encoder.Encode(config); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to encode config: %w", err)
	}

	return tmpFile.Name(), nil
}

func (st *SpeedTester) startXrayProcess(ctx context.Context, configFile string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, st.xrayPath, "run", "-config", configFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Set process attributes based on OS
	setProcAttributes(cmd)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start xray: %w", err)
	}

	st.processManager.RegisterProcess(cmd.Process.Pid, cmd)
	return cmd, nil
}

func (st *SpeedTester) RunSpeedTests(configFile string, maxConfigs int) error {
	configs, err := st.LoadWorkingConfigs(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configs: %w", err)
	}

	if len(configs) == 0 {
		return fmt.Errorf("no valid configurations found")
	}

	if maxConfigs > 0 && len(configs) > maxConfigs {
		configs = configs[:maxConfigs]
	}

	log.Printf("Testing speed for %d configurations with %d concurrent workers...", len(configs), st.concurrent)

	var results []SpeedTestResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, st.concurrent)
	processed := int64(0)
	successful := int64(0)

	progressTicker := time.NewTicker(15 * time.Second)
	defer progressTicker.Stop()

	go func() {
		for {
			select {
			case <-progressTicker.C:
				current := atomic.LoadInt64(&processed)
				success := atomic.LoadInt64(&successful)
				if current > 0 {
					log.Printf("Progress: %d/%d processed (%.1f%%), %d successful (%.1f%%)",
						current, len(configs), float64(current)*100/float64(len(configs)),
						success, float64(success)*100/float64(current))
				}
			case <-st.ctx.Done():
				return
			}
		}
	}()

	for i, config := range configs {
		select {
		case <-st.ctx.Done():
			break
		default:
		}

		wg.Add(1)
		go func(idx int, cfg WorkingConfig) {
			defer wg.Done()
			defer func() { <-semaphore }()

			select {
			case semaphore <- struct{}{}:
			case <-st.ctx.Done():
				return
			}

			testCtx, cancel := context.WithTimeout(st.ctx, st.timeout)
			defer cancel()

			result, err := st.TestConfigSpeed(testCtx, &cfg)
			atomic.AddInt64(&processed, 1)

			if err != nil {
				return
			}

			if result.Success {
				atomic.AddInt64(&successful, 1)
			}

			mu.Lock()
			results = append(results, *result)
			mu.Unlock()

			if idx%20 == 0 {
				runtime.GC()
			}
		}(i, config)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-st.ctx.Done():
		wg.Wait()
	}

	st.categorizeResults(results)

	if err := st.SaveResults(results); err != nil {
		return fmt.Errorf("failed to save results: %w", err)
	}

	st.printSpeedSummary(results)
	return nil
}

func (st *SpeedTester) categorizeResults(results []SpeedTestResult) {
	var successfulResults []SpeedTestResult
	for i, result := range results {
		if result.Success && result.DownloadSpeed > 0 {
			successfulResults = append(successfulResults, results[i])
		}
	}

	if len(successfulResults) == 0 {
		return
	}

	sort.Slice(successfulResults, func(i, j int) bool {
		return successfulResults[i].DownloadSpeed > successfulResults[j].DownloadSpeed
	})

	totalSuccessful := len(successfulResults)
	fastCount := int(math.Max(1, math.Ceil(float64(totalSuccessful)*0.2)))
	mediumCount := int(math.Max(1, math.Ceil(float64(totalSuccessful)*0.3)))
	slowCount := totalSuccessful - fastCount - mediumCount

	if slowCount < 0 {
		slowCount = 0
		mediumCount = totalSuccessful - fastCount
		if mediumCount < 0 {
			mediumCount = 0
			fastCount = totalSuccessful
		}
	}

	index := 0
	for ; index < fastCount && index < totalSuccessful; index++ {
		successfulResults[index].Category = SpeedFast
	}
	for ; index < fastCount+mediumCount && index < totalSuccessful; index++ {
		successfulResults[index].Category = SpeedMedium
	}
	for ; index < totalSuccessful; index++ {
		successfulResults[index].Category = SpeedSlow
	}

	resultMap := make(map[string]*SpeedTestResult)
	for i := range successfulResults {
		key := fmt.Sprintf("%s:%d", successfulResults[i].Config.Server, successfulResults[i].Config.Port)
		resultMap[key] = &successfulResults[i]
	}

	for i := range results {
		if !results[i].Success {
			continue
		}
		key := fmt.Sprintf("%s:%d", results[i].Config.Server, results[i].Config.Port)
		if successful, exists := resultMap[key]; exists {
			results[i].Category = successful.Category
		}
	}
}

func (st *SpeedTester) SaveResults(results []SpeedTestResult) error {
	outputDir := filepath.Join(st.baseDir, "data", "speed_results")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	var fast, medium, slow []SpeedTestResult
	for _, result := range results {
		if result.Success {
			switch result.Category {
			case SpeedFast:
				fast = append(fast, result)
			case SpeedMedium:
				medium = append(medium, result)
			case SpeedSlow:
				slow = append(slow, result)
			}
		}
	}

	sort.Slice(fast, func(i, j int) bool { return fast[i].DownloadSpeed > fast[j].DownloadSpeed })
	sort.Slice(medium, func(i, j int) bool { return medium[i].DownloadSpeed > medium[j].DownloadSpeed })
	sort.Slice(slow, func(i, j int) bool { return slow[i].DownloadSpeed > slow[j].DownloadSpeed })

	if err := st.saveCategory(outputDir, "fast_configs", fast); err != nil {
		return err
	}
	if err := st.saveCategory(outputDir, "medium_configs", medium); err != nil {
		return err
	}
	if err := st.saveCategory(outputDir, "slow_configs", slow); err != nil {
		return err
	}

	return st.saveSummary(outputDir, results)
}

func (st *SpeedTester) saveCategory(outputDir, filename string, results []SpeedTestResult) error {
	if len(results) == 0 {
		return nil
	}

	filePath := filepath.Join(outputDir, filename+".txt")
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	categoryName := strings.Title(strings.ReplaceAll(filename, "_", " "))

	file.WriteString(fmt.Sprintf("# %s Speed Test Results\n", categoryName))
	file.WriteString(fmt.Sprintf("# Generated at: %s\n", timestamp))
	file.WriteString(fmt.Sprintf("# Total configurations: %d\n\n", len(results)))

	for _, result := range results {
		configURL := st.createConfigURL(&result)
		file.WriteString(fmt.Sprintf("# Speed: %.2f Mbps | Time: %.2fs | Size: %d bytes\n",
			result.DownloadSpeed, result.TestTime, result.FileSize))
		file.WriteString(fmt.Sprintf("%s\n\n", configURL))
	}

	return nil
}

func (st *SpeedTester) saveSummary(outputDir string, results []SpeedTestResult) error {
	filePath := filepath.Join(outputDir, "speed_summary.txt")
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create summary file: %w", err)
	}
	defer file.Close()

	var stats struct {
		fast, medium, slow, failed int
		totalSpeed, maxSpeed, minSpeed float64
	}
	stats.minSpeed = math.MaxFloat64

	for _, result := range results {
		if result.Success {
			stats.totalSpeed += result.DownloadSpeed
			if result.DownloadSpeed > stats.maxSpeed {
				stats.maxSpeed = result.DownloadSpeed
			}
			if result.DownloadSpeed < stats.minSpeed {
				stats.minSpeed = result.DownloadSpeed
			}

			switch result.Category {
			case SpeedFast:
				stats.fast++
			case SpeedMedium:
				stats.medium++
			case SpeedSlow:
				stats.slow++
			}
		} else {
			stats.failed++
		}
	}

	successful := len(results) - stats.failed
	avgSpeed := 0.0
	if successful > 0 {
		avgSpeed = stats.totalSpeed / float64(successful)
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString("# Proxy Speed Test Summary\n")
	file.WriteString(fmt.Sprintf("# Generated at: %s\n\n", timestamp))
	file.WriteString(fmt.Sprintf("Total configurations tested: %d\n", len(results)))
	file.WriteString(fmt.Sprintf("Successful tests: %d\n", successful))
	file.WriteString(fmt.Sprintf("Failed tests: %d\n", stats.failed))
	file.WriteString(fmt.Sprintf("Average speed: %.2f Mbps\n", avgSpeed))
	file.WriteString(fmt.Sprintf("Maximum speed: %.2f Mbps\n", stats.maxSpeed))
	if stats.minSpeed != math.MaxFloat64 {
		file.WriteString(fmt.Sprintf("Minimum speed: %.2f Mbps\n", stats.minSpeed))
	}
	file.WriteString("\nSpeed Distribution:\n")
	if len(results) > 0 {
		file.WriteString(fmt.Sprintf("  Fast (Top 20%%): %d (%.1f%%)\n",
			stats.fast, float64(stats.fast)*100/float64(len(results))))
		file.WriteString(fmt.Sprintf("  Medium (Next 30%%): %d (%.1f%%)\n",
			stats.medium, float64(stats.medium)*100/float64(len(results))))
		file.WriteString(fmt.Sprintf("  Slow (Bottom 50%%): %d (%.1f%%)\n",
			stats.slow, float64(stats.slow)*100/float64(len(results))))
	}

	return nil
}

func (st *SpeedTester) createConfigURL(result *SpeedTestResult) string {
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
		if config.TLS != "" && config.TLS != "none" {
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

func (st *SpeedTester) printSpeedSummary(results []SpeedTestResult) {
	var stats struct {
		fast, medium, slow, failed int
		totalSpeed, maxSpeed, minSpeed float64
	}
	stats.minSpeed = math.MaxFloat64

	for _, result := range results {
		if result.Success {
			stats.totalSpeed += result.DownloadSpeed
			if result.DownloadSpeed > stats.maxSpeed {
				stats.maxSpeed = result.DownloadSpeed
			}
			if result.DownloadSpeed < stats.minSpeed {
				stats.minSpeed = result.DownloadSpeed
			}

			switch result.Category {
			case SpeedFast:
				stats.fast++
			case SpeedMedium:
				stats.medium++
			case SpeedSlow:
				stats.slow++
			}
		} else {
			stats.failed++
		}
	}

	successful := len(results) - stats.failed
	avgSpeed := 0.0
	if successful > 0 {
		avgSpeed = stats.totalSpeed / float64(successful)
	}

	separator := strings.Repeat("=", 65)
	log.Println(separator)
	log.Println("SPEED TESTING SUMMARY")
	log.Println(separator)
	log.Printf("Total configurations tested: %d", len(results))
	log.Printf("Successful tests: %d (%.1f%%)", successful, float64(successful)*100/float64(len(results)))
	log.Printf("Failed tests: %d (%.1f%%)", stats.failed, float64(stats.failed)*100/float64(len(results)))
	if successful > 0 {
		log.Printf("Average speed: %.2f Mbps", avgSpeed)
		log.Printf("Maximum speed: %.2f Mbps", stats.maxSpeed)
		if stats.minSpeed != math.MaxFloat64 {
			log.Printf("Minimum speed: %.2f Mbps", stats.minSpeed)
		}
		log.Println()
		log.Printf("Fast (Top 20%%): %d (%.1f%%)", stats.fast, float64(stats.fast)*100/float64(len(results)))
		log.Printf("Medium (Next 30%%): %d (%.1f%%)", stats.medium, float64(stats.medium)*100/float64(len(results)))
		log.Printf("Slow (Bottom 50%%): %d (%.1f%%)", stats.slow, float64(stats.slow)*100/float64(len(results)))
	}
	log.Println()
	log.Println("Results saved to:")
	log.Println("  data/speed_results/fast_configs.txt")
	log.Println("  data/speed_results/medium_configs.txt")
	log.Println("  data/speed_results/slow_configs.txt")
	log.Println("  data/speed_results/speed_summary.txt")
	log.Println(separator)
}

func (st *SpeedTester) Cleanup() {
	st.cancel()
	st.processManager.Cleanup()
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()

	configFile := "data/working_json/working_all_configs.txt"
	maxConfigs := 10000
	concurrent := 4

	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}
	if len(os.Args) > 2 {
		if mc, err := strconv.Atoi(os.Args[2]); err == nil && mc > 0 {
			maxConfigs = mc
		}
	}
	if len(os.Args) > 3 {
		if c, err := strconv.Atoi(os.Args[3]); err == nil && c > 0 && c <= 10 {
			concurrent = c
		}
	}

	log.Printf("Speed Test Configuration:")
	log.Printf("  Config file: %s", configFile)
	log.Printf("  Max configs: %d", maxConfigs)
	log.Printf("  Concurrent connections: %d", concurrent)
	log.Printf("  Available CPU cores: %d", runtime.NumCPU())

	runtime.GOMAXPROCS(runtime.NumCPU())

	tester := NewSpeedTester(ctx, "", 300, concurrent)
	defer tester.Cleanup()

	if err := tester.RunSpeedTests(configFile, maxConfigs); err != nil {
		log.Fatalf("Speed testing failed: %v", err)
	}

	log.Println("Speed testing completed successfully!")
}

// setProcAttributes sets platform-specific process attributes
func setProcAttributes(cmd *exec.Cmd) {
	// For Windows compatibility, we skip setting Setpgid
	// On Unix/Linux, Setpgid would create a new process group,
	// but it's not critical for basic functionality
	if runtime.GOOS != "windows" {
		// Note: Setpgid functionality disabled for cross-platform compatibility
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
}
