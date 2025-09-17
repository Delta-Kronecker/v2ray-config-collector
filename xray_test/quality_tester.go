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
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

type QualityScore int

const (
	ScoreExcellent QualityScore = 1
	ScoreVeryGood  QualityScore = 2
	ScoreGood      QualityScore = 3
	ScoreFair      QualityScore = 4
	ScorePoor      QualityScore = 5
)

type PortManager struct {
	startPort      int
	endPort        int
	availablePorts chan int
	usedPorts      sync.Map
	mu             sync.Mutex
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
	xrayPath       string
	portManager    *PortManager
	processManager *ProcessManager
	testSites      []TestSite
	maxRetries     int
	timeout        time.Duration
	concurrent     int
}

type TestSite struct {
	Name        string
	URL         string
	ExpectedStr string
	Category    string
}

func NewQualityTester(xrayPath string, concurrent int) *QualityTester {
	if xrayPath == "" {
		xrayPath = findXrayExecutable()
	}

	testSites := []TestSite{
		// سایت‌های فیلتر شده در ایران - اولویت اول (پایدارترین)
		{"Twitter", "https://twitter.com", "twitter", "filtered_primary"},
		{"YouTube", "https://www.youtube.com", "watch", "filtered_primary"},
		{"Instagram", "https://www.instagram.com", "instagram", "filtered_primary"},
		{"Discord", "https://discord.com", "discord", "filtered_primary"},
		{"Telegram Web", "https://web.telegram.org", "telegram", "filtered_secondary"},
	}

	return &QualityTester{
		xrayPath:       xrayPath,
		portManager:    NewPortManager(21000, 30000),
		processManager: NewProcessManager(),
		testSites:      testSites,
		maxRetries:     3,
		timeout:        30 * time.Second,   // Standard timeout for GitHub workflows
		concurrent:     concurrent,
	}
}

func (qt *QualityTester) LoadWorkingConfigs(filePath string) ([]WorkingConfig, error) {
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

func (qt *QualityTester) TestConfigQuality(config *WorkingConfig) (*ConfigResult, error) {
	proxyPort, ok := qt.portManager.GetAvailablePort()
	if !ok {
		return nil, fmt.Errorf("no available port")
	}
	defer qt.portManager.ReleasePort(proxyPort)

	xrayConfig, err := qt.generateXrayConfig(config, proxyPort)
	if err != nil {
		log.Printf("Failed to generate config for %s:%d - %v", config.Server, config.Port, err)
		return nil, err
	}

	configFile, err := qt.writeConfigToTempFile(xrayConfig)
	if err != nil {
		log.Printf("Failed to write config file for %s:%d - %v", config.Server, config.Port, err)
		return nil, err
	}
	defer os.Remove(configFile)

	process, err := qt.startXrayProcess(configFile)
	if err != nil {
		log.Printf("Failed to start Xray for %s:%d - %v", config.Server, config.Port, err)
		return nil, err
	}
	defer func() {
		if process != nil && process.Process != nil {
			qt.processManager.KillProcess(process.Process.Pid)
		}
	}()

	time.Sleep(5 * time.Second)

	if process.ProcessState != nil && process.ProcessState.Exited() {
		log.Printf("Xray process exited for %s:%d", config.Server, config.Port)
		return nil, fmt.Errorf("xray process exited")
	}

	results := qt.runQualityTests(proxyPort)

	result := &ConfigResult{
		Config:       *config,
		QualityTests: results,
		TestTime:     time.Now(),
	}

	qt.calculateQualityMetrics(result)
	// دسته‌بندی در SaveResults انجام می‌شود

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

	semaphore := make(chan struct{}, qt.concurrent)

	log.Printf("🔄 Starting quality tests for %d sites via port %d...", totalTests, proxyPort)

	for _, site := range qt.testSites {
		wg.Add(1)
		go func(testSite TestSite) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := qt.testSingleSite(proxyPort, testSite)

			mu.Lock()
			results = append(results, result)
			completed++
			log.Printf("📊 Progress: %d/%d tests completed (%.1f%%) - Last: %s",
				completed, totalTests, float64(completed)/float64(totalTests)*100, testSite.Name)
			mu.Unlock()
		}(site)
	}

	wg.Wait()
	log.Printf("✅ All quality tests completed for port %d", proxyPort)
	return results
}

func (qt *QualityTester) testSingleSite(proxyPort int, site TestSite) TestResult {
	result := TestResult{
		Site: site.Name,
	}

	// برای سایت‌های حیاتی (فیلتر شده در ایران) تست پایداری انجام دهیم
	if qt.isCriticalSite(site.Name) {
		return qt.testSiteStability(proxyPort, site)
	}

	for attempt := 0; attempt <= qt.maxRetries; attempt++ {
		success, latency, downloadTime, contentSize, statusCode, err := qt.performRequest(proxyPort, site.URL, site.ExpectedStr)

		if success {
			result.Success = true
			result.Latency = latency
			result.DownloadTime = downloadTime
			result.ContentSize = contentSize
			result.StatusCode = statusCode
			log.Printf("✓ %s via port %d: %.0fms (HTTP %d, %d bytes)", 
				site.Name, proxyPort, latency, statusCode, contentSize)
			break
		}

		if attempt == qt.maxRetries {
			result.Success = false
			if err != nil {
				result.ErrorMsg = err.Error()
			}
			if statusCode > 0 {
				log.Printf("✗ %s via port %d: Failed (HTTP %d) - %v", 
					site.Name, proxyPort, statusCode, err)
			} else {
				log.Printf("✗ %s via port %d: Failed - %v", 
					site.Name, proxyPort, err)
			}
		}

		time.Sleep(time.Duration(attempt+1) * time.Second)
	}

	return result
}

// تشخیص سایت‌های حیاتی که نیاز به تست پایداری دارند
func (qt *QualityTester) isCriticalSite(siteName string) bool {
	criticalSites := []string{"Twitter", "Instagram", "YouTube", "Discord"}
	for _, critical := range criticalSites {
		if siteName == critical {
			return true
		}
	}
	return false
}

// تست پایداری اتصال با چندین تلاش در فواصل زمانی مختلف
func (qt *QualityTester) testSiteStability(proxyPort int, site TestSite) TestResult {
	result := TestResult{
		Site: site.Name,
	}

	stabilityTests := []time.Duration{
		0 * time.Second,          // فوری
		2 * time.Second,          // بعد از 2 ثانیه
		5 * time.Second,          // بعد از 5 ثانیه
		10 * time.Second,         // بعد از 10 ثانیه
	}

	successCount := 0
	totalLatency := 0.0
	totalDownloadTime := 0.0
	totalContentSize := int64(0)
	lastStatusCode := 0

	log.Printf("🔄 Testing stability for %s via port %d...", site.Name, proxyPort)

	for i, delay := range stabilityTests {
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
			log.Printf("  ✓ Attempt %d/%d: %.0fms", i+1, len(stabilityTests), latency)
		} else {
			log.Printf("  ✗ Attempt %d/%d: Failed - %v", i+1, len(stabilityTests), err)
		}
	}

	// محاسبه نتیجه نهایی بر اساس پایداری
	stabilityRate := float64(successCount) / float64(len(stabilityTests))

	if stabilityRate >= 0.75 { // حداقل 75% موفقیت
		result.Success = true
		result.Latency = totalLatency / float64(successCount)
		result.DownloadTime = totalDownloadTime / float64(successCount)
		result.ContentSize = totalContentSize / int64(successCount)
		result.StatusCode = lastStatusCode

		log.Printf("✓ %s via port %d: STABLE (%.1f%% success, avg %.0fms)", 
			site.Name, proxyPort, stabilityRate*100, result.Latency)
	} else {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("Unstable connection: only %.1f%% success rate", stabilityRate*100)

		log.Printf("✗ %s via port %d: UNSTABLE (%.1f%% success)", 
			site.Name, proxyPort, stabilityRate*100)
	}

	return result
}

func (qt *QualityTester) performRequest(proxyPort int, url, expectedContent string) (bool, float64, float64, int64, int, error) {
	log.Printf("Testing URL %s through proxy port %d", url, proxyPort)

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		log.Printf("Failed to create SOCKS5 dialer: %v", err)
		return false, 0, 0, 0, 0, err
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:     true,
		DisableCompression:    false,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,     // Standard timeout for GitHub
		TLSHandshakeTimeout:   15 * time.Second,     // Standard TLS timeout
		ExpectContinueTimeout: 2 * time.Second,      // Standard timeout
		ResponseHeaderTimeout: 20 * time.Second,     // Standard header timeout
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   qt.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false, 0, 0, 0, 0, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Connection", "keep-alive")

	connectTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, 0, 0, 0, err
	}
	defer resp.Body.Close()

	latency := time.Since(connectTime).Seconds() * 1000

	downloadStart := time.Now()
	body, err := io.ReadAll(resp.Body)
	downloadTime := time.Since(downloadStart).Seconds() * 1000

	if err != nil {
		return false, latency, 0, 0, resp.StatusCode, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, latency, downloadTime, int64(len(body)), resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	bodyStr := string(body)
	if expectedContent != "" {
		bodyLower := strings.ToLower(bodyStr)
		expectedLower := strings.ToLower(expectedContent)

		if expectedContent == "origin" {
			if !strings.Contains(bodyLower, expectedLower) {
				return false, latency, downloadTime, int64(len(body)), resp.StatusCode, fmt.Errorf("expected content not found")
			}
		} else if len(bodyStr) < 500 {
			return false, latency, downloadTime, int64(len(body)), resp.StatusCode, fmt.Errorf("content too small, possibly blocked")
		} else if strings.Contains(bodyLower, "access denied") || strings.Contains(bodyLower, "403 forbidden") || strings.Contains(bodyLower, "blocked") {
			return false, latency, downloadTime, int64(len(body)), resp.StatusCode, fmt.Errorf("access appears to be blocked")
		}
	}

	return true, latency, downloadTime, int64(len(body)), resp.StatusCode, nil
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
		stdDev := math.Sqrt(variance / float64(len(latencies)))
		result.Stability = math.Max(0, 100-(stdDev/result.AvgLatency*100))
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

	// محاسبه امتیاز براساس اولویت سایت‌های فیلتر شده در ایران
	iranFilteredScore := qt.calculateIranFilteredScore(result.QualityTests)

	// Optimized weights for GitHub Actions environment
	filteredSitesWeight := 0.50  // Primary focus: filtered sites accessibility
	latencyWeight := 0.25        // Connection quality
	stabilityWeight := 0.15      // Stability
	speedWeight := 0.10          // Speed

	latencyScore := 100.0
	if result.AvgLatency > 0 {
		// Latency calculation optimized for GitHub Actions environment
		// Under 1 second = full score, above 5 seconds = zero score
		latencyScore = math.Max(0, 100-((result.AvgLatency-1000)/4000*100))
		if latencyScore < 0 {
			latencyScore = 0
		}
		if result.AvgLatency <= 1000 {
			latencyScore = 100
		}
	}

	stabilityScore := result.Stability
	speedScore := math.Min(100, result.Speed*10)

	finalScore := (iranFilteredScore*filteredSitesWeight +
		latencyScore*latencyWeight +
		stabilityScore*stabilityWeight +
		speedScore*speedWeight)

	// اضافه کردن امتیاز اضافی برای پروکسی‌هایی که Twitter و Facebook را باز می‌کنند
	bonusScore := qt.calculateBonusScore(result.QualityTests)
	finalScore += bonusScore

	return math.Round(finalScore*100) / 100
}

// محاسبه امتیاز براساس دسترسی به سایت‌های فیلتر شده ایران
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

	// تمام وزن به سایت‌های اولویت اول داده می‌شود
	primaryScore := float64(primarySuccessCount) / float64(len(primaryFilteredSites)) * 100

	return primaryScore
}





// امتیاز اضافی برای پروکسی‌های عالی
func (qt *QualityTester) calculateBonusScore(tests []TestResult) float64 {
	criticalSites := []string{"Twitter", "Instagram", "YouTube", "Discord"}
	successCount := 0

	for _, test := range tests {
		if test.Success && test.Latency < 800 { // Latency under 800ms for GitHub workflows
			for _, site := range criticalSites {
				if test.Site == site {
					successCount++
					break
				}
			}
		}
	}

	// امتیاز اضافی برای پروکسی‌هایی که همه سایت‌های مهم را با سرعت بالا باز می‌کنند
	if successCount == len(criticalSites) {
		return 10.0 // امتیاز اضافی 10 درصد
	} else if successCount >= len(criticalSites)*3/4 {
		return 5.0  // امتیاز اضافی 5 درصد
	}

	return 0
}



// بررسی دسترسی به سایت‌های فیلتر شده کلیدی
func (qt *QualityTester) checkCriticalSitesAccess(tests []TestResult) float64 {
	criticalSites := []string{"Twitter", "Instagram", "YouTube", "Discord"}
	successCount := 0

	for _, test := range tests {
		if test.Success {
			for _, site := range criticalSites {
				if test.Site == site {
					successCount++
					break
				}
			}
		}
	}

	return float64(successCount) / float64(len(criticalSites))
}

// دسته‌بندی کانفیگ‌ها بر اساس رتبه نسبی
func (qt *QualityTester) categorizeByRank(results []ConfigResult) {
	if len(results) == 0 {
		return
	}

	// مرتب‌سازی بر اساس امتیاز نهایی (بالا به پایین)
	sort.Slice(results, func(i, j int) bool {
		return results[i].FinalScore > results[j].FinalScore
	})

	totalCount := len(results)

	// محاسبه تعداد کانفیگ در هر دسته
	excellentCount := int(float64(totalCount) * 0.10)    // 10% اول
	veryGoodCount := int(float64(totalCount) * 0.20)     // 20% بعدی
	goodCount := int(float64(totalCount) * 0.30)         // 30% بعدی
	fairCount := int(float64(totalCount) * 0.25)         // 25% بعدی
	// باقی در دسته Poor قرار می‌گیرند (15%)

	// اطمینان از اینکه همه کانفیگ‌ها پوشش داده شوند
	if excellentCount == 0 && totalCount > 0 {
		excellentCount = 1
	}

	// اختصاص دسته‌ها
	index := 0

	// دسته Excellent (10% اول)
	for i := 0; i < excellentCount && index < totalCount; i++ {
		results[index].Category = ScoreExcellent
		index++
	}

	// دسته Very Good (20% بعدی)
	for i := 0; i < veryGoodCount && index < totalCount; i++ {
		results[index].Category = ScoreVeryGood
		index++
	}

	// دسته Good (30% بعدی)
	for i := 0; i < goodCount && index < totalCount; i++ {
		results[index].Category = ScoreGood
		index++
	}

	// دسته Fair (25% بعدی)
	for i := 0; i < fairCount && index < totalCount; i++ {
		results[index].Category = ScoreFair
		index++
	}

	// باقی در دسته Poor
	for index < totalCount {
		results[index].Category = ScorePoor
		index++
	}

	log.Printf("📊 Rank-based categorization completed:")
	log.Printf("   Excellent: %d configs (%.1f%%)", excellentCount, float64(excellentCount)/float64(totalCount)*100)
	log.Printf("   Very Good: %d configs (%.1f%%)", veryGoodCount, float64(veryGoodCount)/float64(totalCount)*100)
	log.Printf("   Good: %d configs (%.1f%%)", goodCount, float64(goodCount)/float64(totalCount)*100)
	log.Printf("   Fair: %d configs (%.1f%%)", fairCount, float64(fairCount)/float64(totalCount)*100)
	log.Printf("   Poor: %d configs (%.1f%%)", totalCount-index+fairCount, float64(totalCount-index+fairCount)/float64(totalCount)*100)
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

func (qt *QualityTester) startXrayProcess(configFile string) (*exec.Cmd, error) {
	cmd := exec.Command(qt.xrayPath, "run", "-config", configFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	qt.processManager.RegisterProcess(cmd.Process.Pid, cmd)
	return cmd, nil
}

func (qt *QualityTester) SaveResults(results []ConfigResult) error {
	os.MkdirAll("../data/quality_results", 0755)

	// دسته‌بندی مبتنی بر رتبه (percentile-based)
	qt.categorizeByRank(results)

	excellent := []ConfigResult{}
	veryGood := []ConfigResult{}
	good := []ConfigResult{}
	fair := []ConfigResult{}
	poor := []ConfigResult{}

	for _, result := range results {
		switch result.Category {
		case ScoreExcellent:
			excellent = append(excellent, result)
		case ScoreVeryGood:
			veryGood = append(veryGood, result)
		case ScoreGood:
			good = append(good, result)
		case ScoreFair:
			fair = append(fair, result)
		case ScorePoor:
			poor = append(poor, result)
		}
	}

	sort.Slice(excellent, func(i, j int) bool {
		return excellent[i].FinalScore > excellent[j].FinalScore
	})
	sort.Slice(veryGood, func(i, j int) bool {
		return veryGood[i].FinalScore > veryGood[j].FinalScore
	})
	sort.Slice(good, func(i, j int) bool {
		return good[i].FinalScore > good[j].FinalScore
	})
	sort.Slice(fair, func(i, j int) bool {
		return fair[i].FinalScore > fair[j].FinalScore
	})
	sort.Slice(poor, func(i, j int) bool {
		return poor[i].FinalScore > poor[j].FinalScore
	})

	if err := qt.saveCategory("excellent", excellent); err != nil {
		return err
	}
	if err := qt.saveCategory("very_good", veryGood); err != nil {
		return err
	}
	if err := qt.saveCategory("good", good); err != nil {
		return err
	}
	if err := qt.saveCategory("fair", fair); err != nil {
		return err
	}
	if err := qt.saveCategory("poor", poor); err != nil {
		return err
	}

	return qt.saveSummary(results)
}

func (qt *QualityTester) saveCategory(category string, results []ConfigResult) error {
	if len(results) == 0 {
		return nil
	}

	fileName := fmt.Sprintf("../data/quality_results/%s_configs.txt", category)
	file, err := os.Create(fileName)
	if err != nil {
		return err
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
	fileName := "../data/quality_results/summary.txt"
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	excellentCount := 0
	veryGoodCount := 0
	goodCount := 0
	fairCount := 0
	poorCount := 0
	totalScore := 0.0

	for _, result := range results {
		totalScore += result.FinalScore
		switch result.Category {
		case ScoreExcellent:
			excellentCount++
		case ScoreVeryGood:
			veryGoodCount++
		case ScoreGood:
			goodCount++
		case ScoreFair:
			fairCount++
		case ScorePoor:
			poorCount++
		}
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
		excellentCount, float64(excellentCount)/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Very Good (Next 20%% Best): %d (%.1f%%)\n", 
		veryGoodCount, float64(veryGoodCount)/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Good (Next 30%% Best): %d (%.1f%%)\n", 
		goodCount, float64(goodCount)/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Fair (Next 25%% Best): %d (%.1f%%)\n", 
		fairCount, float64(fairCount)/float64(len(results))*100))
	file.WriteString(fmt.Sprintf("  Poor (Bottom 15%%): %d (%.1f%%)\n", 
		poorCount, float64(poorCount)/float64(len(results))*100))

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

func (qt *QualityTester) RunQualityTests(configFile string, maxConfigs int) error {
	log.Println("Loading working configurations...")
	configs, err := qt.LoadWorkingConfigs(configFile)
	if err != nil {
		return err
	}

	if maxConfigs > 0 && len(configs) > maxConfigs {
		configs = configs[:maxConfigs]
	}

	log.Printf("🚀 Testing quality for %d configurations with %d test sites each...", len(configs), len(qt.testSites))

	var results []ConfigResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, qt.concurrent)
	processed := 0
	totalConfigs := len(configs)

	for _, config := range configs {
		wg.Add(1)
		go func(cfg WorkingConfig) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, err := qt.TestConfigQuality(&cfg)
			if err != nil {
				log.Printf("❌ Failed to test config %s:%d - %v", cfg.Server, cfg.Port, err)
				mu.Lock()
				processed++
				log.Printf("📈 Overall Progress: %d/%d configs tested (%.1f%%) - Failed: %s:%d",
					processed, totalConfigs, float64(processed)/float64(totalConfigs)*100, cfg.Server, cfg.Port)
				mu.Unlock()
				return
			}

			mu.Lock()
			results = append(results, *result)
			processed++
			log.Printf("📈 Overall Progress: %d/%d configs tested (%.1f%%) - Score: %.1f | Success: %.1f%% | Latency: %.0fms",
				processed, totalConfigs, float64(processed)/float64(totalConfigs)*100,
				result.FinalScore, result.SuccessRate, result.AvgLatency)
			mu.Unlock()

			log.Printf("✅ Config %s:%d completed - Score: %.1f, Success: %.1f%%, Latency: %.0fms",
				cfg.Server, cfg.Port, result.FinalScore, result.SuccessRate, result.AvgLatency)
		}(config)
	}

	wg.Wait()

	log.Printf("Quality testing completed. Saving results...")
	if err := qt.SaveResults(results); err != nil {
		return err
	}

	qt.printQualitySummary(results)
	return nil
}

func (qt *QualityTester) printQualitySummary(results []ConfigResult) {
	excellentCount := 0
	veryGoodCount := 0
	goodCount := 0
	fairCount := 0
	poorCount := 0
	totalScore := 0.0

	for _, result := range results {
		totalScore += result.FinalScore
		switch result.Category {
		case ScoreExcellent:
			excellentCount++
		case ScoreVeryGood:
			veryGoodCount++
		case ScoreGood:
			goodCount++
		case ScoreFair:
			fairCount++
		case ScorePoor:
			poorCount++
		}
	}

	avgScore := totalScore / float64(len(results))

	log.Println("=" + strings.Repeat("=", 60))
	log.Println("QUALITY TESTING SUMMARY")
	log.Println("=" + strings.Repeat("=", 60))
	log.Printf("Total configurations tested: %d", len(results))
	log.Printf("Average quality score: %.1f", avgScore)
	log.Println()
	log.Printf("Excellent (Top 10%% Best): %d (%.1f%%)", 
		excellentCount, float64(excellentCount)/float64(len(results))*100)
	log.Printf("Very Good (Next 20%% Best): %d (%.1f%%)", 
		veryGoodCount, float64(veryGoodCount)/float64(len(results))*100)
	log.Printf("Good (Next 30%% Best): %d (%.1f%%)", 
		goodCount, float64(goodCount)/float64(len(results))*100)
	log.Printf("Fair (Next 25%% Best): %d (%.1f%%)", 
		fairCount, float64(fairCount)/float64(len(results))*100)
	log.Printf("Poor (Others): %d (%.1f%%)", 
		poorCount, float64(poorCount)/float64(len(results))*100)
	log.Println()
	log.Println("Results saved to:")
	log.Println("  ../data/quality_results/excellent_configs.txt")
	log.Println("  ../data/quality_results/very_good_configs.txt")
	log.Println("  ../data/quality_results/good_configs.txt")
	log.Println("  ../data/quality_results/fair_configs.txt")
	log.Println("  ../data/quality_results/poor_configs.txt")
	log.Println("  ../data/quality_results/summary.txt")
	log.Println("=" + strings.Repeat("=", 60))
}

func (qt *QualityTester) Cleanup() {
	qt.processManager.Cleanup()
}

func main() {
	configFile := "../data/working_json/working_all_configs.txt"
	maxConfigs := 10000
	concurrent := 12 // Increased concurrent connections for GitHub Actions

	tester := NewQualityTester("", concurrent)
	defer tester.Cleanup()

	if err := tester.RunQualityTests(configFile, maxConfigs); err != nil {
		log.Fatalf("Quality testing failed: %v", err)
	}
}
