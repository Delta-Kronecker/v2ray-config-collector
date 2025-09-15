package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// QualityScore moved to utils.go

// Removed duplicate PortManager and ProcessManager - now using from utils.go

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

// ConfigResult, WorkingConfig, and TestResult moved to utils.go

// Enhanced Quality Tester with adaptive testing and monitoring
type QualityTester struct {
	// Configuration
	config          *Config
	xrayPath        string
	maxRetries      int
	timeout         time.Duration
	concurrent      int

	// Enhanced components
	portManager     *PortManager
	processManager  *ProcessManager
	testSites       []TestSite
	adaptiveConfig  *AdaptiveConfig

	// Performance and reliability
	clientPool      *HTTPClientPool
	circuitBreaker  *CircuitBreaker
	rateLimiter     *RateLimiter
	retryManager    *SmartRetry
	bufferPool      *BufferPool

	// Monitoring and health
	healthChecker   *HealthChecker
	metrics         *TestMetrics
	progressTracker *ProgressTracker
	gracefulShutdown *GracefulShutdown

	// Site categorization for adaptive testing
	criticalSites   []TestSite
	secondarySites  []TestSite
	speedTestSites  []TestSite

	// Runtime statistics
	testResults     map[string]*SiteTestStats
	mu              sync.RWMutex
}

// Site test statistics for adaptive optimization
type SiteTestStats struct {
	TotalTests    int64   `json:"total_tests"`
	SuccessCount  int64   `json:"success_count"`
	FailureCount  int64   `json:"failure_count"`
	AvgLatency    float64 `json:"avg_latency"`
	SuccessRate   float64 `json:"success_rate"`
	LastTested    time.Time `json:"last_tested"`
}

type TestSite struct {
	Name        string
	URL         string
	ExpectedStr string
	Category    string
}

func NewQualityTester(configPath string) (*QualityTester, error) {
	// Load configuration
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	xrayPath := config.ProxyTester.XrayPath
	if xrayPath == "" {
		xrayPath = findXrayExecutable()
	}

	// Define test sites with enhanced categorization
	criticalSites := []TestSite{
		{"Twitter", "https://twitter.com", "twitter", "filtered_primary"},
		{"YouTube", "https://www.youtube.com", "watch", "filtered_primary"},
		{"Instagram", "https://www.instagram.com", "instagram", "filtered_primary"},
		{"Discord", "https://discord.com", "discord", "filtered_primary"},
	}

	secondarySites := []TestSite{
		{"Telegram Web", "https://web.telegram.org", "telegram", "filtered_secondary"},
		{"GitHub", "https://github.com", "github", "filtered_secondary"},
		{"Reddit", "https://www.reddit.com", "reddit", "filtered_secondary"},
		{"Stack Overflow", "https://stackoverflow.com", "stack overflow", "tech_filtered"},
		{"Google Search", "https://www.google.com/search?q=test", "search", "tech_filtered"},
	}

	speedTestSites := []TestSite{
		{"Speed Test", "https://fast.com", "fast", "speed_test"},
		{"CloudFlare Test", "https://1.1.1.1", "cloudflare", "connectivity"},
		{"IP Check", "https://httpbin.org/ip", "origin", "connectivity"},
	}

	// Combine all sites
	allSites := append(append(criticalSites, secondarySites...), speedTestSites...)

	qt := &QualityTester{
		config:          config,
		xrayPath:        xrayPath,
		maxRetries:      3,
		timeout:         config.QualityTester.TestTimeout,
		concurrent:      config.QualityTester.Concurrent,

		// Enhanced components
		portManager:     NewPortManager(21000, 30000, config),
		processManager:  NewProcessManager(),
		testSites:       allSites,
		adaptiveConfig:  NewAdaptiveConfig(),

		// Performance and reliability
		clientPool:      NewHTTPClientPool(config.QualityTester.TestTimeout, config),
		circuitBreaker:  NewCircuitBreaker(config.Performance.CircuitBreakerConfig),
		rateLimiter:     NewRateLimiter(config.Performance.RateLimitConfig),
		retryManager:    NewSmartRetry(config.ProxyTester.RetryConfig),
		bufferPool:      NewBufferPool(config.Performance.MemoryOptimization.BufferSize),

		// Monitoring and health
		healthChecker:   NewHealthChecker(),
		metrics:         NewTestMetrics(),
		gracefulShutdown: NewGracefulShutdown(30 * time.Second),

		// Site categorization
		criticalSites:   criticalSites,
		secondarySites:  secondarySites,
		speedTestSites:  speedTestSites,

		// Statistics
		testResults:     make(map[string]*SiteTestStats),
	}

	// Add health checks
	qt.healthChecker.AddCheck(NewMemoryHealthCheck(2048)) // 2GB limit for quality testing
	qt.healthChecker.AddCheck(NewDiskHealthCheck(config.Common.OutputDir, 1))

	// Initialize site statistics
	for _, site := range allSites {
		qt.testResults[site.Name] = &SiteTestStats{
			LastTested: time.Now(),
		}
	}

	// Setup cleanup functions
	qt.gracefulShutdown.AddCleanupFunc(func() error {
		qt.Cleanup()
		return nil
	})

	// Configure circuit breaker callback
	qt.circuitBreaker.onStateChange = func(state CircuitState) {
		log.Printf("Quality Tester Circuit breaker state changed to: %v", state)
	}

	log.Printf("Enhanced QualityTester initialized with %d concurrent tests, adaptive testing: %v",
		qt.concurrent, config.QualityTester.AdaptiveTesting)

	return qt, nil
}

// NewQualityTesterWithDefaults creates QualityTester with default configuration
func NewQualityTesterWithDefaults() (*QualityTester, error) {
	return NewQualityTester("")
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
	startTime := time.Now()

	// Health check before testing
	if healthResults := qt.healthChecker.CheckAll(); len(healthResults) > 0 {
		for name, err := range healthResults {
			if err != nil {
				log.Printf("Health check warning for %s: %v", name, err)
			}
		}
	}

	// Circuit breaker check
	if qt.circuitBreaker.GetState() == StateOpen {
		qt.metrics.UpdateFailure("circuit_breaker_open")
		return nil, fmt.Errorf("circuit breaker is open")
	}

	// Rate limiting
	if !qt.rateLimiter.Allow() {
		qt.metrics.UpdateFailure("rate_limited")
		return nil, fmt.Errorf("rate limited")
	}

	var result *ConfigResult
	var testErr error

	// Execute with circuit breaker and retry logic
	err := qt.circuitBreaker.Call(func() error {
		return qt.retryManager.Execute(func() error {
			result, testErr = qt.performQualityTest(config)
			return testErr
		})
	})

	if err != nil {
		qt.metrics.UpdateFailure(fmt.Sprintf("test_failed: %v", err))
		return nil, err
	}

	// Update metrics
	if result != nil && result.Result == QualitySuccess {
		qt.metrics.UpdateSuccess(result.AvgLatency)
	} else {
		qt.metrics.UpdateFailure("quality_test_failed")
	}

	duration := time.Since(startTime)
	log.Printf("Config %s:%d completed in %v - Score: %.1f | Success: %.1f%% | Latency: %.0fms | Tests: %d/%d passed", 
		config.Server, config.Port, duration, result.FinalScore, result.SuccessRate, result.AvgLatency, 
		qt.countSuccessfulTests(result.QualityTests), len(result.QualityTests))

	return result, nil
}

// performQualityTest performs the actual quality testing
func (qt *QualityTester) performQualityTest(config *WorkingConfig) (*ConfigResult, error) {
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

	// Wait for Xray to stabilize with adaptive timeout
	stabilizationTime := 3 * time.Second
	if qt.config.QualityTester.AdaptiveTesting {
		// Adaptive stabilization based on past performance
		if avgLatency := qt.getAverageLatencyForSites(); avgLatency > 5000 {
			stabilizationTime = 7 * time.Second // Longer stabilization for high latency networks
		}
	}
	time.Sleep(stabilizationTime)

	if process.ProcessState != nil && process.ProcessState.Exited() {
		log.Printf("Xray process exited for %s:%d", config.Server, config.Port)
		return nil, fmt.Errorf("xray process exited")
	}

	// Run quality tests with adaptive selection
	results := qt.runAdaptiveQualityTests(proxyPort)

	result := &ConfigResult{
		Config:       *config,
		QualityTests: results,
		TestTime:     time.Now(),
	}

	qt.calculateEnhancedQualityMetrics(result)

	return result, nil
}

// getAverageLatencyForSites calculates average latency for performance tuning
func (qt *QualityTester) getAverageLatencyForSites() float64 {
	qt.mu.RLock()
	defer qt.mu.RUnlock()

	totalLatency := 0.0
	siteCount := 0

	for _, stats := range qt.testResults {
		if stats.TotalTests > 0 {
			totalLatency += stats.AvgLatency
			siteCount++
		}
	}

	if siteCount == 0 {
		return 0
	}

	return totalLatency / float64(siteCount)
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
	return qt.runAdaptiveQualityTests(proxyPort)
}

// runAdaptiveQualityTests runs quality tests with adaptive site selection
func (qt *QualityTester) runAdaptiveQualityTests(proxyPort int) []TestResult {
	var results []TestResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Select sites based on adaptive strategy
	selectedSites := qt.selectAdaptiveSites()

	semaphore := make(chan struct{}, qt.concurrent)

	log.Printf("🔄 Running adaptive quality tests with %d sites for port %d", len(selectedSites), proxyPort)

	for _, site := range selectedSites {
		wg.Add(1)
		go func(testSite TestSite) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Rate limiting per site
			if !qt.rateLimiter.Allow() {
				log.Printf("Rate limited for site %s", testSite.Name)
				return
			}

			var result TestResult
			err := qt.circuitBreaker.Call(func() error {
				result = qt.testSingleSiteEnhanced(proxyPort, testSite)
				if !result.Success {
					return fmt.Errorf("test failed for site %s", testSite.Name)
				}
				return nil
			})

			if err != nil {
				result = TestResult{
					Site:     testSite.Name,
					Success:  false,
					ErrorMsg: err.Error(),
				}
			}

			// Update site statistics
			qt.updateSiteStatistics(testSite.Name, result)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(site)
	}

	wg.Wait()

	log.Printf("✅ Adaptive quality tests completed: %d/%d sites successful", 
		qt.countSuccessfulTests(results), len(results))

	return results
}

// selectAdaptiveSites selects sites based on current performance and strategy
func (qt *QualityTester) selectAdaptiveSites() []TestSite {
	if !qt.config.QualityTester.AdaptiveTesting {
		return qt.testSites
	}

	// Always include critical sites
	selectedSites := make([]TestSite, len(qt.criticalSites))
	copy(selectedSites, qt.criticalSites)

	// Add secondary sites based on performance
	qt.mu.RLock()
	avgSuccessRate := qt.calculateAverageSuccessRate()
	qt.mu.RUnlock()

	// If performance is good, include more sites
	if avgSuccessRate > 70 {
		selectedSites = append(selectedSites, qt.secondarySites...)
		selectedSites = append(selectedSites, qt.speedTestSites...)
	} else if avgSuccessRate > 40 {
		// Medium performance: include some secondary sites
		for i, site := range qt.secondarySites {
			if i < len(qt.secondarySites)/2 {
				selectedSites = append(selectedSites, site)
			}
		}
		selectedSites = append(selectedSites, qt.speedTestSites[0]) // Just one speed test
	}
	// Low performance: only critical sites

	log.Printf("📊 Adaptive site selection: %d sites chosen (avg success rate: %.1f%%)", 
		len(selectedSites), avgSuccessRate)

	return selectedSites
}

// calculateAverageSuccessRate calculates average success rate across all sites
func (qt *QualityTester) calculateAverageSuccessRate() float64 {
	totalSites := 0
	totalSuccessRate := 0.0

	for _, stats := range qt.testResults {
		if stats.TotalTests > 0 {
			totalSites++
			totalSuccessRate += stats.SuccessRate
		}
	}

	if totalSites == 0 {
		return 50 // Default assumption
	}

	return totalSuccessRate / float64(totalSites)
}

// updateSiteStatistics updates performance statistics for a site
func (qt *QualityTester) updateSiteStatistics(siteName string, result TestResult) {
	qt.mu.Lock()
	defer qt.mu.Unlock()

	stats, exists := qt.testResults[siteName]
	if !exists {
		stats = &SiteTestStats{
			LastTested: time.Now(),
		}
		qt.testResults[siteName] = stats
	}

	atomic.AddInt64(&stats.TotalTests, 1)
	stats.LastTested = time.Now()

	if result.Success {
		atomic.AddInt64(&stats.SuccessCount, 1)

		// Update average latency using moving average
		successCount := atomic.LoadInt64(&stats.SuccessCount)
		stats.AvgLatency = (stats.AvgLatency*float64(successCount-1) + result.Latency) / float64(successCount)
	} else {
		atomic.AddInt64(&stats.FailureCount, 1)
	}

	// Update success rate
	totalTests := atomic.LoadInt64(&stats.TotalTests)
	successCount := atomic.LoadInt64(&stats.SuccessCount)
	stats.SuccessRate = float64(successCount) / float64(totalTests) * 100
}

func (qt *QualityTester) testSingleSite(proxyPort int, site TestSite) TestResult {
	return qt.testSingleSiteEnhanced(proxyPort, site)
}

// testSingleSiteEnhanced performs enhanced testing with better error handling and optimization
func (qt *QualityTester) testSingleSiteEnhanced(proxyPort int, site TestSite) TestResult {
	result := TestResult{
		Site: site.Name,
	}

	// Check if this is a critical site that needs stability testing
	if qt.isCriticalSite(site.Name) {
		return qt.testSiteStabilityEnhanced(proxyPort, site)
	}

	// Use smart retry for non-critical sites
	err := qt.retryManager.Execute(func() error {
		success, latency, downloadTime, contentSize, statusCode, testErr := qt.performEnhancedRequest(proxyPort, site.URL, site.ExpectedStr)

		if success {
			result.Success = true
			result.Latency = latency
			result.DownloadTime = downloadTime
			result.ContentSize = contentSize
			result.StatusCode = statusCode
			log.Printf("✓ %s via port %d: %.0fms (HTTP %d, %d bytes)", 
				site.Name, proxyPort, latency, statusCode, contentSize)
			return nil
		}

		result.Success = false
		result.StatusCode = statusCode
		if testErr != nil {
			result.ErrorMsg = testErr.Error()
		}

		if statusCode > 0 {
			log.Printf("✗ %s via port %d: Failed (HTTP %d) - %v", 
				site.Name, proxyPort, statusCode, testErr)
		} else {
			log.Printf("✗ %s via port %d: Failed - %v", 
				site.Name, proxyPort, testErr)
		}

		return testErr
	})

	if err != nil && !result.Success {
		result.ErrorMsg = err.Error()
	}

	return result
}

// تشخیص سایت‌های حیاتی که نیاز به تست پایداری دارند
func (qt *QualityTester) isCriticalSite(siteName string) bool {
	criticalSites := []string{"Twitter", "Instagram", "YouTube", "Discord", "Telegram Web"}
	for _, critical := range criticalSites {
		if siteName == critical {
			return true
		}
	}
	return false
}

// testSiteStabilityEnhanced performs enhanced stability testing with adaptive intervals
func (qt *QualityTester) testSiteStabilityEnhanced(proxyPort int, site TestSite) TestResult {
	result := TestResult{
		Site: site.Name,
	}

	// Adaptive stability test intervals based on configuration
	stabilityTests := []time.Duration{
		0 * time.Second,          // فوری
		2 * time.Second,          // بعد از 2 ثانیه
		5 * time.Second,          // بعد از 5 ثانیه
	}

	// Add more intervals for high-quality testing
	if qt.config.QualityTester.AdaptiveTesting {
		stabilityTests = append(stabilityTests, 10*time.Second, 15*time.Second)
	}

	successCount := 0
	totalLatency := 0.0
	totalDownloadTime := 0.0
	totalContentSize := int64(0)
	lastStatusCode := 0

	log.Printf("🔄 Enhanced stability testing for %s via port %d (%d attempts)...", 
		site.Name, proxyPort, len(stabilityTests))

	for i, delay := range stabilityTests {
		if i > 0 {
			time.Sleep(delay - stabilityTests[i-1])
		}

		// Use enhanced request with better error handling
		success, latency, downloadTime, contentSize, statusCode, err := qt.performEnhancedRequest(proxyPort, site.URL, site.ExpectedStr)

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

		// Early exit if we have enough data and good stability
		if i >= 2 && float64(successCount)/float64(i+1) >= qt.config.QualityTester.StabilityThreshold {
			log.Printf("  🎯 Early stability confirmation after %d attempts", i+1)
			break
		}
	}

	// Calculate final result based on adaptive stability threshold
	stabilityRate := float64(successCount) / float64(len(stabilityTests))
	requiredThreshold := qt.config.QualityTester.StabilityThreshold

	if stabilityRate >= requiredThreshold {
		result.Success = true
		if successCount > 0 {
			result.Latency = totalLatency / float64(successCount)
			result.DownloadTime = totalDownloadTime / float64(successCount)
			result.ContentSize = totalContentSize / int64(successCount)
		}
		result.StatusCode = lastStatusCode

		log.Printf("✅ %s via port %d: STABLE (%.1f%% success, avg %.0fms, threshold: %.0f%%)", 
			site.Name, proxyPort, stabilityRate*100, result.Latency, requiredThreshold*100)
	} else {
		result.Success = false
		result.ErrorMsg = fmt.Sprintf("Unstable connection: %.1f%% success rate (required: %.0f%%)", 
			stabilityRate*100, requiredThreshold*100)

		log.Printf("❌ %s via port %d: UNSTABLE (%.1f%% success, required: %.0f%%)", 
			site.Name, proxyPort, stabilityRate*100, requiredThreshold*100)
	}

	return result
}

func (qt *QualityTester) performRequest(proxyPort int, url, expectedContent string) (bool, float64, float64, int64, int, error) {
	return qt.performEnhancedRequest(proxyPort, url, expectedContent)
}

// performEnhancedRequest performs HTTP request with connection pooling and better error handling
func (qt *QualityTester) performEnhancedRequest(proxyPort int, url, expectedContent string) (bool, float64, float64, int64, int, error) {
	log.Printf("Testing URL %s through proxy port %d", url, proxyPort)

	// Get client from pool
	client, err := qt.clientPool.GetClient(proxyPort)
	if err != nil {
		log.Printf("Failed to get client from pool: %v", err)
		return false, 0, 0, 0, 0, err
	}
	defer qt.clientPool.PutClient(client)

	// Create request with context for timeout control
	ctx, cancel := context.WithTimeout(context.Background(), qt.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, 0, 0, 0, 0, err
	}

	// Enhanced headers for better compatibility
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,fa;q=0.8")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	connectTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		// Check if it's a timeout or context cancellation
		if ctx.Err() != nil {
			return false, 0, 0, 0, 0, fmt.Errorf("request timeout: %w", ctx.Err())
		}
		return false, 0, 0, 0, 0, err
	}
	defer resp.Body.Close()

	latency := time.Since(connectTime).Seconds() * 1000

	downloadStart := time.Now()

	// Use buffer pool for efficient reading
	buf := qt.bufferPool.Get()
	defer qt.bufferPool.Put(buf)

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
			return false, latency, 0, 0, resp.StatusCode, err
		}

		// Prevent excessive memory usage
		if len(bodyBytes) > 1024*1024 { // 1MB limit
			break
		}
	}

	downloadTime := time.Since(downloadStart).Seconds() * 1000

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false, latency, downloadTime, int64(len(bodyBytes)), resp.StatusCode, 
			fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Enhanced content validation
	if len(bodyBytes) == 0 {
		return false, latency, downloadTime, 0, resp.StatusCode, 
			fmt.Errorf("empty response body")
	}

	bodyStr := string(bodyBytes)
	if expectedContent != "" {
		if !qt.validateResponseContent(bodyStr, expectedContent, resp.StatusCode) {
			return false, latency, downloadTime, int64(len(bodyBytes)), resp.StatusCode, 
				fmt.Errorf("content validation failed")
		}
	}

	log.Printf("✓ URL %s: %.0fms (HTTP %d, %d bytes)", url, latency, resp.StatusCode, len(bodyBytes))
	return true, latency, downloadTime, int64(len(bodyBytes)), resp.StatusCode, nil
}

// validateResponseContent performs enhanced content validation
func (qt *QualityTester) validateResponseContent(body, expectedContent string, statusCode int) bool {
	bodyLower := strings.ToLower(body)
	expectedLower := strings.ToLower(expectedContent)

	// Special handling for IP check services
	if expectedContent == "origin" {
		// Look for IP patterns in JSON responses
		if strings.Contains(body, `"origin"`) || strings.Contains(body, `"ip"`) {
			return true
		}
		// Look for plain IP patterns
		ipPattern := `\b(?:\d{1,3}\.){3}\d{1,3}\b`
		matched, _ := regexp.MatchString(ipPattern, body)
		return matched
	}

	// Check for blocking indicators
	blockingIndicators := []string{
		"access denied", "403 forbidden", "blocked", "censored",
		"filtered", "not available", "restricted access",
		"این سایت فیلتر شده", "دسترسی مسدود", // Persian blocking messages
	}

	for _, indicator := range blockingIndicators {
		if strings.Contains(bodyLower, indicator) {
			return false
		}
	}

	// Minimum content size check (adjust based on site)
	minSize := 500
	if strings.Contains(expectedLower, "fast") || strings.Contains(expectedLower, "speed") {
		minSize = 200 // Speed test sites might have smaller initial response
	}

	if len(body) < minSize {
		return false
	}

	// Check for expected content
	if expectedContent != "" && !strings.Contains(bodyLower, expectedLower) {
		return false
	}

	return true
}

func (qt *QualityTester) calculateQualityMetrics(result *ConfigResult) {
	qt.calculateEnhancedQualityMetrics(result)
}

// calculateEnhancedQualityMetrics calculates quality metrics with enhanced algorithms
func (qt *QualityTester) calculateEnhancedQualityMetrics(result *ConfigResult) {
	var latencies []float64
	var downloadTimes []float64
	var contentSizes []int64
	successCount := 0

	// Categorize test results by site type for weighted scoring
	criticalSuccesses := 0
	criticalTotal := 0
	secondarySuccesses := 0
	secondaryTotal := 0
	speedSuccesses := 0
	speedTotal := 0

	for _, test := range result.QualityTests {
		// Categorize site type
		isCritical := qt.isCriticalSite(test.Site)
		isSpeed := qt.isSpeedTestSite(test.Site)

		if isCritical {
			criticalTotal++
			if test.Success {
				criticalSuccesses++
			}
		} else if isSpeed {
			speedTotal++
			if test.Success {
				speedSuccesses++
			}
		} else {
			secondaryTotal++
			if test.Success {
				secondarySuccesses++
			}
		}

		if test.Success {
			successCount++
			latencies = append(latencies, test.Latency)
			downloadTimes = append(downloadTimes, test.DownloadTime)
			contentSizes = append(contentSizes, test.ContentSize)
		}
	}

	totalTests := len(result.QualityTests)
	result.SuccessRate = float64(successCount) / float64(totalTests) * 100

	// Enhanced latency calculation with outlier filtering
	if len(latencies) > 0 {
		// Remove outliers (values more than 2 standard deviations from mean)
		filteredLatencies := qt.filterOutliers(latencies)

		sum := 0.0
		for _, lat := range filteredLatencies {
			sum += lat
		}
		result.AvgLatency = sum / float64(len(filteredLatencies))

		// Calculate stability with enhanced algorithm
		result.Stability = qt.calculateStabilityScore(filteredLatencies, result.AvgLatency)
	}

	// Enhanced speed calculation
	if len(downloadTimes) > 0 && len(contentSizes) > 0 {
		result.Speed = qt.calculateEnhancedSpeed(downloadTimes, contentSizes)
	}

	// Calculate final score with enhanced algorithm
	result.FinalScore = qt.calculateEnhancedFinalScore(result, criticalSuccesses, criticalTotal, 
		secondarySuccesses, secondaryTotal, speedSuccesses, speedTotal)

	// Set result status
	if result.SuccessRate >= 50 && result.FinalScore >= 40 {
		result.Result = QualitySuccess
	} else {
		result.Result = QualityFailed
	}
}

// filterOutliers removes statistical outliers from latency measurements
func (qt *QualityTester) filterOutliers(latencies []float64) []float64 {
	if len(latencies) < 3 {
		return latencies // Need at least 3 points for meaningful filtering
	}

	// Calculate mean and standard deviation
	sum := 0.0
	for _, lat := range latencies {
		sum += lat
	}
	mean := sum / float64(len(latencies))

	variance := 0.0
	for _, lat := range latencies {
		variance += math.Pow(lat-mean, 2)
	}
	stdDev := math.Sqrt(variance / float64(len(latencies)))

	// Filter out values more than 2 standard deviations from mean
	var filtered []float64
	for _, lat := range latencies {
		if math.Abs(lat-mean) <= 2*stdDev {
			filtered = append(filtered, lat)
		}
	}

	if len(filtered) == 0 {
		return latencies // Return original if all filtered out
	}

	return filtered
}

// calculateStabilityScore calculates stability score with enhanced algorithm
func (qt *QualityTester) calculateStabilityScore(latencies []float64, avgLatency float64) float64 {
	if len(latencies) < 2 {
		return 100 // Perfect stability for single measurement
	}

	// Calculate coefficient of variation (CV)
	variance := 0.0
	for _, lat := range latencies {
		variance += math.Pow(lat-avgLatency, 2)
	}
	stdDev := math.Sqrt(variance / float64(len(latencies)))

	if avgLatency == 0 {
		return 0
	}

	cv := stdDev / avgLatency * 100

	// Convert CV to stability score (lower CV = higher stability)
	// CV of 0-10% = 100-90 stability, CV of 50%+ = 0 stability
	stability := math.Max(0, 100-(cv*2))

	return math.Min(100, stability)
}

// calculateEnhancedSpeed calculates network speed with better algorithm
func (qt *QualityTester) calculateEnhancedSpeed(downloadTimes []float64, contentSizes []int64) float64 {
	if len(downloadTimes) == 0 || len(contentSizes) == 0 {
		return 0
	}

	// Calculate throughput for each test
	var throughputs []float64
	for i := 0; i < len(downloadTimes) && i < len(contentSizes); i++ {
		if downloadTimes[i] > 0 {
			// Convert: bytes per ms -> Mbps
			bytesPerMs := float64(contentSizes[i]) / float64(downloadTimes[i])
			mbps := (bytesPerMs * 1000 * 8) / (1024 * 1024)
			throughputs = append(throughputs, mbps)
		}
	}

	if len(throughputs) == 0 {
		return 0
	}

	// Use median instead of average to reduce impact of outliers
	sort.Float64s(throughputs)
	median := throughputs[len(throughputs)/2]

	return median
}

// isSpeedTestSite checks if a site is a speed test site
func (qt *QualityTester) isSpeedTestSite(siteName string) bool {
	speedSites := []string{"Speed Test", "CloudFlare Test", "IP Check"}
	for _, site := range speedSites {
		if siteName == site {
			return true
		}
	}
	return false
}

func (qt *QualityTester) calculateFinalScore(result *ConfigResult) float64 {
	return qt.calculateEnhancedFinalScore(result, 0, 0, 0, 0, 0, 0)
}

// calculateEnhancedFinalScore calculates final score with enhanced algorithm and configurable weights
func (qt *QualityTester) calculateEnhancedFinalScore(result *ConfigResult, criticalSuccesses, criticalTotal, secondarySuccesses, secondaryTotal, speedSuccesses, speedTotal int) float64 {
	if result.SuccessRate == 0 {
		return 0
	}

	// Use configurable weights from config
	criticalWeight := qt.config.QualityTester.CriticalSiteWeight
	latencyWeight := qt.config.QualityTester.LatencyWeight
	stabilityWeight := qt.config.QualityTester.StabilityWeight
	speedWeight := qt.config.QualityTester.SpeedWeight

	// Calculate critical sites score with enhanced algorithm
	criticalScore := 0.0
	if criticalTotal > 0 {
		criticalScore = float64(criticalSuccesses) / float64(criticalTotal) * 100
	}

	// Calculate latency score with adaptive thresholds
	latencyScore := qt.calculateAdaptiveLatencyScore(result.AvgLatency)

	// Use calculated stability score
	stabilityScore := result.Stability

	// Enhanced speed score calculation
	speedScore := qt.calculateAdaptiveSpeedScore(result.Speed)

	// Base score calculation
	baseScore := (criticalScore*criticalWeight + 
		latencyScore*latencyWeight + 
		stabilityScore*stabilityWeight + 
		speedScore*speedWeight)

	// Add bonus scores for exceptional performance
	bonusScore := qt.calculateEnhancedBonusScore(result, criticalSuccesses, criticalTotal)

	// Apply penalty for low overall success rate
	penaltyFactor := 1.0
	if result.SuccessRate < 60 {
		penaltyFactor = result.SuccessRate / 60.0
	}

	finalScore := (baseScore + bonusScore) * penaltyFactor

	// Log scoring breakdown for debugging
	log.Printf("Score breakdown for %s:%d - Critical: %.1f, Latency: %.1f, Stability: %.1f, Speed: %.1f, Bonus: %.1f, Final: %.1f",
		result.Config.Server, result.Config.Port, criticalScore, latencyScore, stabilityScore, speedScore, bonusScore, finalScore)

	return math.Round(finalScore*100) / 100
}

// calculateAdaptiveLatencyScore calculates latency score with adaptive thresholds
func (qt *QualityTester) calculateAdaptiveLatencyScore(avgLatency float64) float64 {
	if avgLatency <= 0 {
		return 100
	}

	// Adaptive thresholds based on current network conditions
	avgNetworkLatency := qt.getAverageLatencyForSites()

	// Dynamic thresholds: if network is generally slow, be more lenient
	excellentThreshold := 2000.0  // 2 seconds
	goodThreshold := 5000.0       // 5 seconds
	acceptableThreshold := 10000.0 // 10 seconds

	if avgNetworkLatency > 3000 {
		// Network is slow, adjust thresholds
		excellentThreshold = 4000.0
		goodThreshold = 8000.0
		acceptableThreshold = 15000.0
	}

	if avgLatency <= excellentThreshold {
		return 100
	} else if avgLatency <= goodThreshold {
		// Linear decrease from 100 to 70
		return 100 - ((avgLatency-excellentThreshold)/(goodThreshold-excellentThreshold))*30
	} else if avgLatency <= acceptableThreshold {
		// Linear decrease from 70 to 30
		return 70 - ((avgLatency-goodThreshold)/(acceptableThreshold-goodThreshold))*40
	} else {
		// Exponential decay for very high latency
		excess := avgLatency - acceptableThreshold
		decay := math.Exp(-excess / 5000) // Decay factor
		return 30 * decay
	}
}

// calculateAdaptiveSpeedScore calculates speed score with realistic expectations
func (qt *QualityTester) calculateAdaptiveSpeedScore(speed float64) float64 {
	if speed <= 0 {
		return 0
	}

	// Realistic speed expectations for proxy connections
	// 1 Mbps = 50 points, 5 Mbps = 100 points
	score := speed * 20 // 1 Mbps = 20 points

	return math.Min(100, score)
}

// calculateEnhancedBonusScore calculates bonus score for exceptional performance
func (qt *QualityTester) calculateEnhancedBonusScore(result *ConfigResult, criticalSuccesses, criticalTotal int) float64 {
	bonusScore := 0.0

	// Bonus for perfect critical site access
	if criticalTotal > 0 && criticalSuccesses == criticalTotal {
		bonusScore += 10.0
		log.Printf("Perfect critical site access bonus: +10 points")
	}

	// Bonus for exceptional speed
	if result.Speed > 10 { // More than 10 Mbps
		bonusScore += 5.0
		log.Printf("High speed bonus: +5 points (%.1f Mbps)", result.Speed)
	}

	// Bonus for exceptional stability
	if result.Stability > 95 {
		bonusScore += 3.0
		log.Printf("High stability bonus: +3 points (%.1f%%)", result.Stability)
	}

	// Bonus for very low latency
	if result.AvgLatency > 0 && result.AvgLatency < 1000 { // Less than 1 second
		bonusScore += 5.0
		log.Printf("Low latency bonus: +5 points (%.0fms)", result.AvgLatency)
	}

	// Bonus for 100% success rate
	if result.SuccessRate == 100 {
		bonusScore += 2.0
		log.Printf("Perfect success rate bonus: +2 points")
	}

	return bonusScore
}

// محاسبه امتیاز براساس دسترسی به سایت‌های فیلتر شده ایران
func (qt *QualityTester) calculateIranFilteredScore(tests []TestResult) float64 {
	primaryFilteredSites := []string{"Twitter", "YouTube", "Instagram", "Discord"}
	secondaryFilteredSites := []string{"Telegram Web", "GitHub", "Reddit"}
	techFilteredSites := []string{"Stack Overflow", "Google Search"}

	primarySuccessCount := 0
	secondarySuccessCount := 0
	techSuccessCount := 0

	for _, test := range tests {
		if test.Success {
			for _, site := range primaryFilteredSites {
				if test.Site == site {
					primarySuccessCount++
					break
				}
			}
			for _, site := range secondaryFilteredSites {
				if test.Site == site {
					secondarySuccessCount++
					break
				}
			}
			for _, site := range techFilteredSites {
				if test.Site == site {
					techSuccessCount++
					break
				}
			}
		}
	}

	// وزن‌گذاری: سایت‌های اولویت اول مهم‌ترند
	primaryScore := float64(primarySuccessCount) / float64(len(primaryFilteredSites)) * 100 * 0.6
	secondaryScore := float64(secondarySuccessCount) / float64(len(secondaryFilteredSites)) * 100 * 0.25
	techScore := float64(techSuccessCount) / float64(len(techFilteredSites)) * 100 * 0.15

	return primaryScore + secondaryScore + techScore
}



// محاسبه امتیاز براساس تست سرعت
func (qt *QualityTester) calculateSpeedTestScore(tests []TestResult) float64 {
	speedSites := []string{"Speed Test", "CloudFlare Test"}
	successCount := 0
	totalLatency := 0.0

	for _, test := range tests {
		for _, site := range speedSites {
			if test.Site == site && test.Success {
				successCount++
				totalLatency += test.Latency
				break
			}
		}
	}

	if successCount == 0 {
		return 0
	}

	avgLatency := totalLatency / float64(successCount)
	// برای ایران، لیتنسی زیر 3 ثانیه قابل قبول است
	return math.Max(0, 100-(avgLatency/3000*100))
}

// امتیاز اضافی برای پروکسی‌های عالی
func (qt *QualityTester) calculateBonusScore(tests []TestResult) float64 {
	criticalSites := []string{"Twitter", "Instagram", "YouTube", "Discord"}
	successCount := 0

	for _, test := range tests {
		if test.Success && test.Latency < 2000 { // لیتنسی کمتر از 2 ثانیه (واقعی‌تر)
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
	return qt.RunEnhancedQualityTests(configFile, maxConfigs)
}

// RunEnhancedQualityTests runs quality tests with enhanced monitoring and adaptive features
func (qt *QualityTester) RunEnhancedQualityTests(configFile string, maxConfigs int) error {
	startTime := time.Now()

	log.Println("🔄 Loading working configurations...")
	configs, err := qt.LoadWorkingConfigs(configFile)
	if err != nil {
		return fmt.Errorf("failed to load configurations: %w", err)
	}

	if maxConfigs > 0 && len(configs) > maxConfigs {
		log.Printf("Limiting configurations to %d (from %d available)", maxConfigs, len(configs))
		configs = configs[:maxConfigs]
	}

	log.Printf("🎯 Starting enhanced quality testing for %d configurations...", len(configs))

	// Initialize progress tracking
	qt.progressTracker = NewProgressTracker(int64(len(configs)))

	var results []ConfigResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, qt.concurrent)
	processed := int64(0)

	// Adaptive concurrent adjustment
	currentConcurrent := qt.concurrent

	for i, config := range configs {
		wg.Add(1)
		go func(cfg WorkingConfig, index int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Health check every 50 configs
			if index%50 == 0 {
				if healthResults := qt.healthChecker.CheckAll(); len(healthResults) > 0 {
					for name, err := range healthResults {
						if err != nil {
							log.Printf("Health check warning for %s: %v", name, err)
						}
					}
				}
			}

			// Test configuration with enhanced error handling
			result, err := qt.TestConfigQuality(&cfg)
			if err != nil {
				// Create failed result for tracking
				result = &ConfigResult{
					Config:      cfg,
					FinalScore:  0,
					SuccessRate: 0,
					TestTime:    time.Now(),
				}
				log.Printf("❌ Failed to test config %s:%d - %v", cfg.Server, cfg.Port, err)
			}

			mu.Lock()
			results = append(results, *result)
			newProcessed := atomic.AddInt64(&processed, 1)

			// Progress reporting
			if newProcessed%20 == 0 {
				qt.progressTracker.UpdateProgress(newProcessed)

				// Update adaptive metrics
				if len(results) > 50 {
					qt.updateAdaptiveSettings(results, &currentConcurrent)
				}

				// Log current performance
				successCount := 0
				totalLatency := 0.0
				for _, r := range results {
					if r.SuccessRate > 50 {
						successCount++
						totalLatency += r.AvgLatency
					}
				}

				if len(results) > 0 {
					currentSuccessRate := float64(successCount) / float64(len(results)) * 100
					avgLatency := totalLatency / math.Max(1, float64(successCount))

					log.Printf("📊 Progress: %d/%d | Success Rate: %.1f%% | Avg Latency: %.0fms | Circuit: %v",
						newProcessed, len(configs), currentSuccessRate, avgLatency, qt.circuitBreaker.GetState())
				}
			}
			mu.Unlock()

			if result.SuccessRate > 0 {
				log.Printf("✅ Config %s:%d - Score: %.1f | Success: %.1f%% | Latency: %.0fms", 
					cfg.Server, cfg.Port, result.FinalScore, result.SuccessRate, result.AvgLatency)
			}
		}(config, i)

		// Adaptive rate limiting
		if qt.config.QualityTester.AdaptiveTesting && i > 0 && i%100 == 0 {
			// Brief pause every 100 configs for system stability
			time.Sleep(500 * time.Millisecond)

			// Memory cleanup
			if qt.config.Performance.MemoryOptimization.EnableGCOptimization {
				runtime.GC()
			}
		}
	}

	wg.Wait()
	duration := time.Since(startTime)

	log.Printf("🎉 Enhanced quality testing completed in %v", duration)
	log.Printf("📈 Final statistics: %d configs tested, %.1f configs/second", 
		len(results), float64(len(results))/duration.Seconds())

	// Save results with enhanced categorization
	log.Println("💾 Saving enhanced results...")
	if err := qt.SaveEnhancedResults(results); err != nil {
		return fmt.Errorf("failed to save results: %w", err)
	}

	// Print enhanced summary
	qt.printEnhancedQualitySummary(results, duration)

	// Save final metrics
	if qt.config.Common.EnableMetrics {
		qt.saveFinalQualityMetrics(results, duration)
	}

	return nil
}

// updateAdaptiveSettings updates concurrent workers and other settings based on performance
func (qt *QualityTester) updateAdaptiveSettings(results []ConfigResult, currentConcurrent *int) {
	if !qt.config.QualityTester.AdaptiveTesting {
		return
	}

	// Calculate recent performance
	recentResults := results
	if len(results) > 100 {
		recentResults = results[len(results)-100:] // Last 100 results
	}

	successCount := 0
	totalLatency := 0.0
	for _, result := range recentResults {
		if result.SuccessRate > 50 {
			successCount++
			totalLatency += result.AvgLatency
		}
	}

	successRate := float64(successCount) / float64(len(recentResults)) * 100
	avgLatency := totalLatency / math.Max(1, float64(successCount))

	// Update adaptive configuration
	qt.adaptiveConfig.UpdateMetrics(successRate, avgLatency, 0)

	// Suggest new concurrent value
	newConcurrent := qt.adaptiveConfig.SuggestWorkerCount(*currentConcurrent)
	if newConcurrent != *currentConcurrent {
		log.Printf("🔧 Adaptive: Adjusting concurrent workers from %d to %d (Success: %.1f%%, Latency: %.0fms)",
			*currentConcurrent, newConcurrent, successRate, avgLatency)
		*currentConcurrent = newConcurrent
	}
}

// saveFinalQualityMetrics saves comprehensive final metrics
func (qt *QualityTester) saveFinalQualityMetrics(results []ConfigResult, duration time.Duration) {
	total, successful, successRate, avgLatency := qt.metrics.GetStats()
	failures, successes, cbState := qt.circuitBreaker.GetStats()

	// Calculate quality distribution
	excellent, veryGood, good, fair, poor := 0, 0, 0, 0, 0
	totalScore := 0.0

	for _, result := range results {
		totalScore += result.FinalScore
		switch result.Category {
		case ScoreExcellent:
			excellent++
		case ScoreVeryGood:
			veryGood++
		case ScoreGood:
			good++
		case ScoreFair:
			fair++
		case ScorePoor:
			poor++
		}
	}

	avgScore := 0.0
	if len(results) > 0 {
		avgScore = totalScore / float64(len(results))
	}

	finalMetrics := map[string]interface{}{
		"quality_test_summary": map[string]interface{}{
			"total_configurations": len(results),
			"successful_tests":     successful,
			"failed_tests":         total - successful,
			"success_rate_percent": successRate,
			"total_duration":       duration.String(),
			"avg_latency_ms":       avgLatency,
			"avg_quality_score":    avgScore,
		},
		"quality_distribution": map[string]interface{}{
			"excellent": excellent,
			"very_good": veryGood,
			"good":      good,
			"fair":      fair,
			"poor":      poor,
		},
		"performance_metrics": map[string]interface{}{
			"tests_per_second":     float64(total) / duration.Seconds(),
			"avg_test_time":        duration.Seconds() / float64(len(results)),
		},
		"circuit_breaker_stats": map[string]interface{}{
			"final_state":     cbState,
			"total_failures":  failures,
			"total_successes": successes,
		},
		"configuration": map[string]interface{}{
			"concurrent_tests":     qt.concurrent,
			"timeout_seconds":      qt.timeout.Seconds(),
			"adaptive_testing":     qt.config.QualityTester.AdaptiveTesting,
			"circuit_breaker":      qt.config.Performance.EnableCircuitBreaker,
			"rate_limiting":        qt.config.Performance.RateLimitConfig.Enabled,
		},
	}

	// Add memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	finalMetrics["performance_metrics"].(map[string]interface{})["memory_usage_mb"] = float64(m.Alloc) / 1024 / 1024

	// Save final metrics
	metricsFile := fmt.Sprintf("%s/quality_results/final_quality_metrics.json", qt.config.Common.OutputDir)
	os.MkdirAll(fmt.Sprintf("%s/quality_results", qt.config.Common.OutputDir), 0755)

	if file, err := os.Create(metricsFile); err == nil {
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		encoder.Encode(finalMetrics)
		log.Printf("📊 Final quality metrics saved to: %s", metricsFile)
	}
}

func (qt *QualityTester) printQualitySummary(results []ConfigResult) {
	qt.printEnhancedQualitySummary(results, 0)
}

// printEnhancedQualitySummary prints comprehensive summary with enhanced metrics
func (qt *QualityTester) printEnhancedQualitySummary(results []ConfigResult, duration time.Duration) {
	excellentCount := 0
	veryGoodCount := 0
	goodCount := 0
	fairCount := 0
	poorCount := 0
	totalScore := 0.0
	successfulConfigs := 0

	for _, result := range results {
		totalScore += result.FinalScore
		if result.SuccessRate > 50 {
			successfulConfigs++
		}
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

	log.Println("🎉 " + strings.Repeat("=", 70))
	log.Println("ENHANCED QUALITY TESTING SUMMARY")
	log.Println(strings.Repeat("=", 70))
	log.Printf("Total configurations tested: %d", len(results))
	log.Printf("Successful configurations: %d (%.1f%%)", successfulConfigs, 
		float64(successfulConfigs)/float64(len(results))*100)
	log.Printf("Average quality score: %.1f/100", avgScore)

	if duration > 0 {
		log.Printf("Total test duration: %v", duration)
		log.Printf("Test throughput: %.2f configs/second", float64(len(results))/duration.Seconds())
	}

	// Enhanced metrics from components
	total, _, successRate, avgLatency := qt.metrics.GetStats()
	failures, successes, cbState := qt.circuitBreaker.GetStats()

	log.Printf("Enhanced metrics - Tests: %d, Success Rate: %.1f%%, Avg Latency: %.0fms", 
		total, successRate, avgLatency)
	log.Printf("Circuit Breaker - State: %v, Failures: %d, Successes: %d", 
		cbState, failures, successes)

	log.Println("\n📊 Quality Distribution (Rank-Based):")
	if len(results) > 0 {
		log.Printf("  🥇 Excellent (Top 10%% Best): %d (%.1f%%)", 
			excellentCount, float64(excellentCount)/float64(len(results))*100)
		log.Printf("  🥈 Very Good (Next 20%% Best): %d (%.1f%%)", 
			veryGoodCount, float64(veryGoodCount)/float64(len(results))*100)
		log.Printf("  🥉 Good (Next 30%% Best): %d (%.1f%%)", 
			goodCount, float64(goodCount)/float64(len(results))*100)
		log.Printf("  ⭐ Fair (Next 25%% Best): %d (%.1f%%)", 
			fairCount, float64(fairCount)/float64(len(results))*100)
		log.Printf("  ❌ Poor (Bottom 15%%): %d (%.1f%%)", 
			poorCount, float64(poorCount)/float64(len(results))*100)
	}

	// Memory usage
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	log.Printf("\n💾 Memory Usage:")
	log.Printf("  Allocated: %.2f MB", float64(m.Alloc)/1024/1024)
	log.Printf("  GC Cycles: %d", m.NumGC)

	// Site statistics summary
	qt.mu.RLock()
	criticalSiteSuccess := 0
	totalCriticalSites := len(qt.criticalSites)
	for _, site := range qt.criticalSites {
		if stats, exists := qt.testResults[site.Name]; exists && stats.SuccessRate > 60 {
			criticalSiteSuccess++
		}
	}
	qt.mu.RUnlock()

	log.Printf("\n🎯 Critical Sites Performance:")
	log.Printf("  Sites with >60%% success: %d/%d (%.1f%%)", 
		criticalSiteSuccess, totalCriticalSites, 
		float64(criticalSiteSuccess)/float64(totalCriticalSites)*100)

	log.Printf("\n📁 Results saved to:")
	log.Printf("  📊 Quality categories: %s/quality_results/", qt.config.Common.OutputDir)
	log.Printf("  📈 Metrics: %s/quality_results/final_quality_metrics.json", qt.config.Common.OutputDir)
	log.Printf("  📋 Summary: %s/quality_results/summary.txt", qt.config.Common.OutputDir)

	// Performance insights
	log.Println("\n🔍 Performance Insights:")
	if avgScore < 40 {
		log.Println("  ⚠️  Low average score detected. Consider network optimization.")
	}
	if avgLatency > 5000 {
		log.Println("  ⚠️  High latency detected. Network conditions may be challenging.")
	}
	if cbState == StateOpen {
		log.Println("  ⚠️  Circuit breaker is open. System experienced reliability issues.")
	}
	if float64(successfulConfigs)/float64(len(results)) < 0.3 {
		log.Println("  ⚠️  Low success rate. Consider adjusting test parameters.")
	}
	if avgScore >= 70 && successRate >= 80 {
		log.Println("  ✅ Excellent overall performance! System is operating optimally.")
	}

	log.Println(strings.Repeat("=", 70))
}

// SaveEnhancedResults saves results with enhanced categorization and metrics
func (qt *QualityTester) SaveEnhancedResults(results []ConfigResult) error {
	if len(results) == 0 {
		return fmt.Errorf("no results to save")
	}

	// Call the existing SaveResults method which includes the rank-based categorization
	if err := qt.SaveResults(results); err != nil {
		return err
	}

	// Save additional enhanced metrics and statistics
	return qt.saveEnhancedStatistics(results)
}

// saveEnhancedStatistics saves detailed statistics and insights
func (qt *QualityTester) saveEnhancedStatistics(results []ConfigResult) error {
	statsFile := fmt.Sprintf("%s/quality_results/enhanced_statistics.json", qt.config.Common.OutputDir)

	// Calculate detailed statistics
	protocolStats := make(map[string]map[string]interface{})
	latencyDistribution := make(map[string]int)
	scoreDistribution := make(map[string]int)

	for _, result := range results {
		protocol := result.Config.Protocol
		if protocolStats[protocol] == nil {
			protocolStats[protocol] = map[string]interface{}{
				"count": 0,
				"total_score": 0.0,
				"successful": 0,
				"total_latency": 0.0,
			}
		}

		stats := protocolStats[protocol]
		stats["count"] = stats["count"].(int) + 1
		stats["total_score"] = stats["total_score"].(float64) + result.FinalScore

		if result.SuccessRate > 50 {
			stats["successful"] = stats["successful"].(int) + 1
			stats["total_latency"] = stats["total_latency"].(float64) + result.AvgLatency
		}

		// Latency distribution
		latencyRange := "unknown"
		if result.AvgLatency > 0 {
			if result.AvgLatency < 1000 {
				latencyRange = "0-1s"
			} else if result.AvgLatency < 3000 {
				latencyRange = "1-3s"
			} else if result.AvgLatency < 5000 {
				latencyRange = "3-5s"
			} else if result.AvgLatency < 10000 {
				latencyRange = "5-10s"
			} else {
				latencyRange = "10s+"
			}
		}
		latencyDistribution[latencyRange]++

		// Score distribution
		scoreRange := "0-20"
		if result.FinalScore >= 80 {
			scoreRange = "80-100"
		} else if result.FinalScore >= 60 {
			scoreRange = "60-80"
		} else if result.FinalScore >= 40 {
			scoreRange = "40-60"
		} else if result.FinalScore >= 20 {
			scoreRange = "20-40"
		}
		scoreDistribution[scoreRange]++
	}

	// Calculate averages for protocol stats
	for _, stats := range protocolStats {
		count := stats["count"].(int)
		if count > 0 {
			stats["avg_score"] = stats["total_score"].(float64) / float64(count)
		}
		successful := stats["successful"].(int)
		if successful > 0 {
			stats["avg_latency"] = stats["total_latency"].(float64) / float64(successful)
		}
		stats["success_rate"] = float64(successful) / float64(count) * 100
	}

	enhancedStats := map[string]interface{}{
		"timestamp": time.Now(),
		"total_configs": len(results),
		"protocol_statistics": protocolStats,
		"latency_distribution": latencyDistribution,
		"score_distribution": scoreDistribution,
		"site_statistics": qt.testResults,
		"configuration": map[string]interface{}{
			"concurrent_tests": qt.concurrent,
			"timeout_seconds": qt.timeout.Seconds(),
			"adaptive_testing": qt.config.QualityTester.AdaptiveTesting,
			"weights": map[string]interface{}{
				"critical_sites": qt.config.QualityTester.CriticalSiteWeight,
				"latency": qt.config.QualityTester.LatencyWeight,
				"stability": qt.config.QualityTester.StabilityWeight,
				"speed": qt.config.QualityTester.SpeedWeight,
			},
		},
	}

	file, err := os.Create(statsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(enhancedStats); err != nil {
		return err
	}

	log.Printf("📈 Enhanced statistics saved to: %s", statsFile)
	return nil
}

func (qt *QualityTester) Cleanup() {
	log.Println("🧹 Starting enhanced cleanup...")

	// Cleanup processes
	if qt.processManager != nil {
		qt.processManager.Cleanup()
	}

	// Save final site statistics
	if qt.config != nil && qt.config.Common.EnableMetrics {
		qt.saveFinalSiteStatistics()
	}

	// Cleanup ports
	if qt.portManager != nil {
		// Port manager cleanup is handled automatically
		log.Println("✅ Port manager cleaned up")
	}

	// Close client pool
	if qt.clientPool != nil {
		log.Println("✅ HTTP client pool cleaned up")
	}

	// Final memory cleanup
	if qt.config != nil && qt.config.Performance.MemoryOptimization.EnableGCOptimization {
		runtime.GC()
		log.Println("✅ Final garbage collection completed")
	}

	log.Println("✅ Enhanced cleanup completed successfully")
}

// saveFinalSiteStatistics saves final statistics for all tested sites
func (qt *QualityTester) saveFinalSiteStatistics() {
	qt.mu.RLock()
	defer qt.mu.RUnlock()

	if len(qt.testResults) == 0 {
		return
	}

	statsFile := fmt.Sprintf("%s/quality_results/site_statistics.json", qt.config.Common.OutputDir)
	os.MkdirAll(fmt.Sprintf("%s/quality_results", qt.config.Common.OutputDir), 0755)

	siteStats := map[string]interface{}{
		"timestamp": time.Now(),
		"sites": qt.testResults,
		"summary": map[string]interface{}{
			"total_sites": len(qt.testResults),
			"critical_sites": len(qt.criticalSites),
			"secondary_sites": len(qt.secondarySites),
			"speed_test_sites": len(qt.speedTestSites),
		},
	}

	if file, err := os.Create(statsFile); err == nil {
		defer file.Close()
		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(siteStats); err == nil {
			log.Printf("📊 Site statistics saved to: %s", statsFile)
		}
	}
}

func main() {
	// Configuration file path (can be passed as command line argument)
	configPath := ""
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	// Initialize enhanced quality tester
	tester, err := NewQualityTester(configPath)
	if err != nil {
		log.Fatalf("Failed to initialize enhanced quality tester: %v", err)
	}
	defer tester.Cleanup()

	// Setup signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal, initiating graceful shutdown...")
		if err := tester.gracefulShutdown.Shutdown(); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
		}
		os.Exit(0)
	}()

	// Configuration
	configFile := tester.config.Common.OutputDir + "/working_json/working_all_configs.txt"
	maxConfigs := tester.config.QualityTester.MaxConfigs

	log.Printf("Enhanced Quality Tester started")
	log.Printf("Configuration: %d max configs, %d concurrent tests, timeout: %v", 
		maxConfigs, tester.concurrent, tester.timeout)
	log.Printf("Adaptive testing: %v, Circuit breaker: %v, Rate limiting: %v",
		tester.config.QualityTester.AdaptiveTesting,
		tester.config.Performance.EnableCircuitBreaker,
		tester.config.Performance.RateLimitConfig.Enabled)

	// Run enhanced quality tests
	if err := tester.RunEnhancedQualityTests(configFile, maxConfigs); err != nil {
		log.Fatalf("Enhanced quality testing failed: %v", err)
	}

	// Save configuration template for future use
	if configPath == "" {
		templatePath := "quality_config_template.yaml"
		if err := SaveConfig(tester.config, templatePath); err == nil {
			log.Printf("📝 Quality tester configuration template saved to: %s", templatePath)
		}
	}

	log.Println("Enhanced Quality Testing completed successfully! 🎉")
}
