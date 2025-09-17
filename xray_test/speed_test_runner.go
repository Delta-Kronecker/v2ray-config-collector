package main

import (
	"bufio"
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
}

type PortManager struct {
	startPort     int
	endPort       int
	availablePorts chan int
	usedPorts     sync.Map
	mu            sync.Mutex
}

func NewPortManager(startPort, endPort int) *PortManager {
	pm := &PortManager{
		startPort:     startPort,
		endPort:       endPort,
		availablePorts: make(chan int, endPort-startPort+1),
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
		pm.usedPorts.Store(port, true)
		return port, true
	case <-time.After(100 * time.Millisecond):
		return pm.findEmergencyPort(), true
	}
}

func (pm *PortManager) findEmergencyPort() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := 0; i < 100; i++ {
		port := pm.startPort + (i * 17) % (pm.endPort - pm.startPort + 1)
		if _, used := pm.usedPorts.Load(port); !used && pm.isPortAvailable(port) {
			pm.usedPorts.Store(port, true)
			return port
		}
	}
	return 0
}

func (pm *PortManager) ReleasePort(port int) {
	pm.usedPorts.Delete(port)
	go func() {
		time.Sleep(20 * time.Millisecond)
		select {
		case pm.availablePorts <- port:
		default:
		}
	}()
}

type ProcessManager struct {
	processes sync.Map
	mu        sync.RWMutex
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
					case <-time.After(300 * time.Millisecond):
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
	pm.processes.Range(func(key, value interface{}) bool {
		if pid, ok := key.(int); ok {
			pm.KillProcess(pid)
		}
		return true
	})
}

type SpeedTester struct {
	xrayPath       string
	portManager    *PortManager
	processManager *ProcessManager
	testServices   []SpeedTestService
	maxWorkers     int
	timeout        time.Duration
	concurrent     int
}

func NewSpeedTester(xrayPath string, maxWorkers int, concurrent int) *SpeedTester {
	if xrayPath == "" {
		xrayPath = findXrayExecutable()
	}

	testServices := []SpeedTestService{
		{
			Name:        "Fast.com",
			URL:         "https://fast.com/app-10mb.png",
			FileSize:    10485760,
			Description: "Fast.com 10MB test file",
		},
		{
			Name:        "Speedtest.net",
			URL:         "https://speedtest.net/__down?bytes=10485760",
			FileSize:    10485760,
			Description: "Speedtest.net 10MB test file",
		},
		{
			Name:        "Cloudflare",
			URL:         "https://speed.cloudflare.com/__down?bytes=10485760",
			FileSize:    10485760,
			Description: "Cloudflare 10MB test file",
		},
	}

	return &SpeedTester{
		xrayPath:       xrayPath,
		portManager:    NewPortManager(30001, 40000),
		processManager: NewProcessManager(),
		testServices:   testServices,
		maxWorkers:     maxWorkers,
		timeout:        180 * time.Second,
		concurrent:     concurrent,
	}
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

func (st *SpeedTester) LoadWorkingConfigs(filePath string) ([]WorkingConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var configs []WorkingConfig
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var config WorkingConfig
		if err := json.Unmarshal([]byte(line), &config); err != nil {
			continue
		}

		configs = append(configs, config)
	}

	return configs, nil
}

func (st *SpeedTester) TestConfigSpeed(config *WorkingConfig) (*SpeedTestResult, error) {
	proxyPort, ok := st.portManager.GetAvailablePort()
	if !ok {
		return nil, fmt.Errorf("no available port")
	}
	defer st.portManager.ReleasePort(proxyPort)

	xrayConfig, err := st.generateXrayConfig(config, proxyPort)
	if err != nil {
		log.Printf("Failed to generate config for %s:%d - %v", config.Server, config.Port, err)
		return nil, err
	}

	configFile, err := st.writeConfigToTempFile(xrayConfig)
	if err != nil {
		log.Printf("Failed to write config file for %s:%d - %v", config.Server, config.Port, err)
		return nil, err
	}
	defer os.Remove(configFile)

	process, err := st.startXrayProcess(configFile)
	if err != nil {
		log.Printf("Failed to start Xray for %s:%d - %v", config.Server, config.Port, err)
		return nil, err
	}
	defer func() {
		if process != nil && process.Process != nil {
			st.processManager.KillProcess(process.Process.Pid)
		}
	}()

	time.Sleep(3 * time.Second)

	if process.ProcessState != nil && process.ProcessState.Exited() {
		log.Printf("Xray process exited for %s:%d", config.Server, config.Port)
		return nil, fmt.Errorf("xray process exited")
	}

	result := &SpeedTestResult{
		Config: *config,
	}

	speed, testTime, testURL, fileSize, err := st.performSpeedTest(proxyPort)
	if err != nil {
		result.Success = false
		result.ErrorMessage = err.Error()
		result.DownloadSpeed = 0
		result.TestTime = testTime
	} else {
		result.Success = true
		result.DownloadSpeed = speed
		result.TestTime = testTime
		result.TestURL = testURL
		result.FileSize = fileSize
	}

	log.Printf("Speed test %s:%d - %.2f Mbps (%.2fs)", config.Server, config.Port, result.DownloadSpeed, result.TestTime)

	return result, nil
}

func (st *SpeedTester) performSpeedTest(proxyPort int) (float64, float64, string, int64, error) {
	var bestSpeed float64
	var bestTime float64
	var bestURL string
	var bestFileSize int64
	var lastErr error

	for _, service := range st.testServices {
		speed, testTime, fileSize, err := st.testSingleService(proxyPort, service)
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

		if speed > 10 {
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

func (st *SpeedTester) testSingleService(proxyPort int, service SpeedTestService) (float64, float64, int64, error) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return 0, 0, 0, err
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:     true,
		DisableCompression:    false,
		MaxIdleConns:          5,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   60 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   st.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", service.URL, nil)
	if err != nil {
		return 0, 0, 0, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")

	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, time.Since(startTime).Seconds(), 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return 0, time.Since(startTime).Seconds(), 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	downloadStart := time.Now()
	body, err := io.ReadAll(resp.Body)
	downloadTime := time.Since(downloadStart).Seconds()
	totalTime := time.Since(startTime).Seconds()

	if err != nil {
		return 0, totalTime, 0, err
	}

	bytesDownloaded := int64(len(body))
	if bytesDownloaded == 0 {
		return 0, totalTime, 0, fmt.Errorf("no data received")
	}

	if downloadTime <= 0 {
		return 0, totalTime, bytesDownloaded, fmt.Errorf("invalid download time")
	}

	speedMbps := (float64(bytesDownloaded) * 8) / (downloadTime * 1024 * 1024)

	return speedMbps, totalTime, bytesDownloaded, nil
}

func (st *SpeedTester) generateXrayConfig(config *WorkingConfig, listenPort int) (map[string]interface{}, error) {
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

func (st *SpeedTester) writeConfigToTempFile(config map[string]interface{}) (string, error) {
	tmpFile, err := os.CreateTemp("", "xray-speed-*.json")
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

func (st *SpeedTester) startXrayProcess(configFile string) (*exec.Cmd, error) {
	cmd := exec.Command(st.xrayPath, "run", "-config", configFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	st.processManager.RegisterProcess(cmd.Process.Pid, cmd)
	return cmd, nil
}

func (st *SpeedTester) RunSpeedTests(configFile string, maxConfigs int) error {
	log.Println("Loading working configurations...")
	configs, err := st.LoadWorkingConfigs(configFile)
	if err != nil {
		return err
	}

	if maxConfigs > 0 && len(configs) > maxConfigs {
		configs = configs[:maxConfigs]
	}

	log.Printf("Testing speed for %d configurations...", len(configs))

	var results []SpeedTestResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, st.concurrent)
	processed := int64(0)

	for _, config := range configs {
		wg.Add(1)
		go func(cfg WorkingConfig) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, err := st.TestConfigSpeed(&cfg)
			if err != nil {
				log.Printf("Failed to test config %s:%d - %v", cfg.Server, cfg.Port, err)
				return
			}

			mu.Lock()
			results = append(results, *result)
			atomic.AddInt64(&processed, 1)
			current := atomic.LoadInt64(&processed)
			if current%10 == 0 {
				log.Printf("Processed %d/%d configurations", current, len(configs))
			}
			mu.Unlock()
		}(config)
	}

	wg.Wait()

	log.Printf("Speed testing completed. Categorizing and saving results...")
	st.categorizeResults(results)
	if err := st.SaveResults(results); err != nil {
		return err
	}

	st.printSpeedSummary(results)
	return nil
}

func (st *SpeedTester) categorizeResults(results []SpeedTestResult) {
	var successfulResults []SpeedTestResult
	for _, result := range results {
		if result.Success && result.DownloadSpeed > 0 {
			successfulResults = append(successfulResults, result)
		}
	}

	if len(successfulResults) == 0 {
		log.Println("No successful speed tests to categorize")
		return
	}

	sort.Slice(successfulResults, func(i, j int) bool {
		return successfulResults[i].DownloadSpeed > successfulResults[j].DownloadSpeed
	})

	totalSuccessful := len(successfulResults)
	fastCount := int(math.Ceil(float64(totalSuccessful) * 0.3))
	mediumCount := int(math.Ceil(float64(totalSuccessful) * 0.3))
	slowCount := totalSuccessful - fastCount - mediumCount

	log.Printf("Categorizing %d successful results: Fast=%d, Medium=%d, Slow=%d",
		totalSuccessful, fastCount, mediumCount, slowCount)

	index := 0
	for _ = 0; index < fastCount && index < totalSuccessful; index++ {
		successfulResults[index].Category = SpeedFast
	}

	for _ = 0; index < fastCount+mediumCount && index < totalSuccessful; index++ {
		successfulResults[index].Category = SpeedMedium
	}

	for index < totalSuccessful {
		successfulResults[index].Category = SpeedSlow
		index++
	}

	for _, successful := range successfulResults {
		for j, result := range results {
			if result.Config.Server == successful.Config.Server &&
			   result.Config.Port == successful.Config.Port {
				results[j].Category = successful.Category
				break
			}
		}
	}
}

func (st *SpeedTester) SaveResults(results []SpeedTestResult) error {
	os.MkdirAll("../data/speed_results", 0755)

	fast := []SpeedTestResult{}
	medium := []SpeedTestResult{}
	slow := []SpeedTestResult{}

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

	sort.Slice(fast, func(i, j int) bool {
		return fast[i].DownloadSpeed > fast[j].DownloadSpeed
	})
	sort.Slice(medium, func(i, j int) bool {
		return medium[i].DownloadSpeed > medium[j].DownloadSpeed
	})
	sort.Slice(slow, func(i, j int) bool {
		return slow[i].DownloadSpeed > slow[j].DownloadSpeed
	})

	if err := st.saveCategory("fast_configs", fast); err != nil {
		return err
	}
	if err := st.saveCategory("medium_configs", medium); err != nil {
		return err
	}
	if err := st.saveCategory("slow_configs", slow); err != nil {
		return err
	}

	return st.saveSummary(results)
}

func (st *SpeedTester) saveCategory(filename string, results []SpeedTestResult) error {
	if len(results) == 0 {
		return nil
	}

	fileName := fmt.Sprintf("../data/speed_results/%s.txt", filename)
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString(fmt.Sprintf("# %s Speed Test Results\n", strings.Title(strings.ReplaceAll(filename, "_", " "))))
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

func (st *SpeedTester) saveSummary(results []SpeedTestResult) error {
	fileName := "../data/speed_results/speed_summary.txt"
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	fastCount := 0
	mediumCount := 0
	slowCount := 0
	failedCount := 0
	totalSpeed := 0.0
	maxSpeed := 0.0
	minSpeed := math.MaxFloat64

	for _, result := range results {
		if result.Success {
			totalSpeed += result.DownloadSpeed
			if result.DownloadSpeed > maxSpeed {
				maxSpeed = result.DownloadSpeed
			}
			if result.DownloadSpeed < minSpeed {
				minSpeed = result.DownloadSpeed
			}

			switch result.Category {
			case SpeedFast:
				fastCount++
			case SpeedMedium:
				mediumCount++
			case SpeedSlow:
				slowCount++
			}
		} else {
			failedCount++
		}
	}

	avgSpeed := 0.0
	if len(results) > failedCount {
		avgSpeed = totalSpeed / float64(len(results)-failedCount)
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	file.WriteString("# Proxy Speed Test Summary\n")
	file.WriteString(fmt.Sprintf("# Generated at: %s\n\n", timestamp))
	file.WriteString(fmt.Sprintf("Total configurations tested: %d\n", len(results)))
	file.WriteString(fmt.Sprintf("Successful tests: %d\n", len(results)-failedCount))
	file.WriteString(fmt.Sprintf("Failed tests: %d\n", failedCount))
	file.WriteString(fmt.Sprintf("Average speed: %.2f Mbps\n", avgSpeed))
	file.WriteString(fmt.Sprintf("Maximum speed: %.2f Mbps\n", maxSpeed))
	if minSpeed != math.MaxFloat64 {
		file.WriteString(fmt.Sprintf("Minimum speed: %.2f Mbps\n", minSpeed))
	}
	file.WriteString("\nSpeed Distribution:\n")
	file.WriteString(fmt.Sprintf("  Fast (Top 30%%): %d (%.1f%%)\n",
		fastCount, float64(fastCount)/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Medium (Next 30%%): %d (%.1f%%)\n",
		mediumCount, float64(mediumCount)/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Slow (Bottom 40%%): %d (%.1f%%)\n",
		slowCount, float64(slowCount)/float64(len(results))*100))

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

func (st *SpeedTester) printSpeedSummary(results []SpeedTestResult) {
	fastCount := 0
	mediumCount := 0
	slowCount := 0
	failedCount := 0
	totalSpeed := 0.0
	maxSpeed := 0.0
	minSpeed := math.MaxFloat64

	for _, result := range results {
		if result.Success {
			totalSpeed += result.DownloadSpeed
			if result.DownloadSpeed > maxSpeed {
				maxSpeed = result.DownloadSpeed
			}
			if result.DownloadSpeed < minSpeed {
				minSpeed = result.DownloadSpeed
			}

			switch result.Category {
			case SpeedFast:
				fastCount++
			case SpeedMedium:
				mediumCount++
			case SpeedSlow:
				slowCount++
			}
		} else {
			failedCount++
		}
	}

	avgSpeed := 0.0
	if len(results) > failedCount {
		avgSpeed = totalSpeed / float64(len(results)-failedCount)
	}

	log.Println("=" + strings.Repeat("=", 60))
	log.Println("SPEED TESTING SUMMARY")
	log.Println("=" + strings.Repeat("=", 60))
	log.Printf("Total configurations tested: %d", len(results))
	log.Printf("Successful tests: %d", len(results)-failedCount)
	log.Printf("Failed tests: %d", failedCount)
	log.Printf("Average speed: %.2f Mbps", avgSpeed)
	log.Printf("Maximum speed: %.2f Mbps", maxSpeed)
	if minSpeed != math.MaxFloat64 {
		log.Printf("Minimum speed: %.2f Mbps", minSpeed)
	}
	log.Println()
	log.Printf("Fast (Top 30%%): %d (%.1f%%)",
		fastCount, float64(fastCount)/float64(len(results))*100)
	log.Printf("Medium (Next 30%%): %d (%.1f%%)",
		mediumCount, float64(mediumCount)/float64(len(results))*100)
	log.Printf("Slow (Bottom 40%%): %d (%.1f%%)",
		slowCount, float64(slowCount)/float64(len(results))*100)
	log.Println()
	log.Println("Results saved to:")
	log.Println("  ../data/speed_results/fast_configs.txt")
	log.Println("  ../data/speed_results/medium_configs.txt")
	log.Println("  ../data/speed_results/slow_configs.txt")
	log.Println("  ../data/speed_results/speed_summary.txt")
	log.Println("=" + strings.Repeat("=", 60))
}

func (st *SpeedTester) Cleanup() {
	st.processManager.Cleanup()
}

func main() {
	configFile := "../data/working_json/working_all_configs.txt"
	maxConfigs := 10000
	concurrent := 8

	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	if len(os.Args) > 2 {
		if mc, err := strconv.Atoi(os.Args[2]); err == nil {
			maxConfigs = mc
		}
	}

	if len(os.Args) > 3 {
		if c, err := strconv.Atoi(os.Args[3]); err == nil {
			concurrent = c
		}
	}

	fmt.Printf("Usage: go run speed_test_runner.go [config_file] [max_configs] [concurrent]\n")
	fmt.Printf("Default config file: %s\n", configFile)
	fmt.Printf("Max configs: %d, Concurrent connections: %d\n\n", maxConfigs, concurrent)

	log.Printf("Starting speed test with config file: %s", configFile)
	log.Printf("Max configs: %d, Concurrent connections: %d", maxConfigs, concurrent)

	tester := NewSpeedTester("", 500, concurrent)
	defer tester.Cleanup()

	if err := tester.RunSpeedTests(configFile, maxConfigs); err != nil {
		log.Fatalf("Speed testing failed: %v", err)
	}

	log.Println("Speed testing completed successfully!")
}
