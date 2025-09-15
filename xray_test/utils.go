package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/time/rate"
)

// Interfaces for dependency injection and testing
type ProxyTesterInterface interface {
	TestSingleConfig(config *ProxyConfig, batchID int) *TestResultData
	TestConfigs(configs []ProxyConfig, batchID int) []*TestResultData
	LoadConfigsFromJSON(filePath string, protocol ProxyProtocol) ([]ProxyConfig, error)
	RunTests(configs []ProxyConfig) []*TestResultData
	Cleanup()
}

type QualityTesterInterface interface {
	TestConfigQuality(config *WorkingConfig) (*ConfigResult, error)
	LoadWorkingConfigs(filePath string) ([]WorkingConfig, error)
	RunQualityTests(configFile string, maxConfigs int) error
	Cleanup()
}

type NetworkTesterInterface interface {
	TestProxyConnection(proxyPort int) (bool, string, float64)
}

type PortManagerInterface interface {
	GetAvailablePort() (int, bool)
	ReleasePort(port int)
	IsPortAvailable(port int) bool
}

type ProcessManagerInterface interface {
	RegisterProcess(pid int, cmd interface{})
	UnregisterProcess(pid int)
	KillProcess(pid int) error
	Cleanup()
}

// Circuit Breaker Pattern Implementation
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

var (
	ErrCircuitOpen = errors.New("circuit breaker is open")
	ErrTooManyRequests = errors.New("too many requests")
)

type CircuitBreaker struct {
	maxFailures   int
	failures      int64
	lastFailure   time.Time
	successCount  int64
	state         CircuitState
	timeout       time.Duration
	resetTimeout  time.Duration
	thresholdRate float64
	mu            sync.RWMutex
	onStateChange func(CircuitState)
}

func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		maxFailures:   config.MaxFailures,
		timeout:       config.Timeout,
		resetTimeout:  config.ResetTimeout,
		thresholdRate: config.ThresholdRate,
		state:         StateClosed,
	}
}

func (cb *CircuitBreaker) Call(fn func() error) error {
	if !cb.canExecute() {
		return ErrCircuitOpen
	}

	err := fn()
	cb.recordResult(err)
	return err
}

func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.setState(StateHalfOpen)
			return true
		}
		return false
	case StateHalfOpen:
		return true
	default:
		return false
	}
}

func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		atomic.AddInt64(&cb.failures, 1)
		cb.lastFailure = time.Now()

		if cb.state == StateHalfOpen {
			cb.setState(StateOpen)
		} else if atomic.LoadInt64(&cb.failures) >= int64(cb.maxFailures) {
			cb.setState(StateOpen)
		}
	} else {
		atomic.AddInt64(&cb.successCount, 1)

		if cb.state == StateHalfOpen {
			cb.setState(StateClosed)
			atomic.StoreInt64(&cb.failures, 0)
		}
	}
}

func (cb *CircuitBreaker) setState(state CircuitState) {
	cb.state = state
	if cb.onStateChange != nil {
		cb.onStateChange(state)
	}
}

func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *CircuitBreaker) GetStats() (int64, int64, CircuitState) {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return atomic.LoadInt64(&cb.failures), atomic.LoadInt64(&cb.successCount), cb.state
}

// HTTP Client Pool for connection reuse
type HTTPClientPool struct {
	clients sync.Pool
	timeout time.Duration
	config  *Config
}

func NewHTTPClientPool(timeout time.Duration, config *Config) *HTTPClientPool {
	pool := &HTTPClientPool{
		timeout: timeout,
		config:  config,
	}

	pool.clients = sync.Pool{
		New: func() interface{} {
			return pool.createNewClient()
		},
	}

	return pool
}

func (p *HTTPClientPool) createNewClient() *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxIdleConns:          p.config.Performance.PoolSize,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       p.config.Performance.PoolTimeout,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   p.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}
}

func (p *HTTPClientPool) GetClient(proxyPort int) (*http.Client, error) {
	client := p.clients.Get().(*http.Client)

	// Configure proxy
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return nil, err
	}

	transport := client.Transport.(*http.Transport)
	transport.Dial = dialer.Dial

	return client, nil
}

func (p *HTTPClientPool) PutClient(client *http.Client) {
	// Reset proxy configuration
	transport := client.Transport.(*http.Transport)
	transport.Dial = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).Dial

	p.clients.Put(client)
}

// Rate Limiter for controlling request rate
type RateLimiter struct {
	limiter *rate.Limiter
	enabled bool
	mu      sync.RWMutex
}

func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(rate.Limit(config.RequestsPerSec), config.BurstSize),
		enabled: config.Enabled,
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if !rl.enabled {
		return true
	}

	return rl.limiter.Allow()
}

func (rl *RateLimiter) Wait(ctx context.Context) error {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	if !rl.enabled {
		return nil
	}

	return rl.limiter.Wait(ctx)
}

func (rl *RateLimiter) SetEnabled(enabled bool) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.enabled = enabled
}

// Smart Retry Logic with exponential backoff and jitter
type SmartRetry struct {
	config RetryConfig
	rand   *rand.Rand
	mu     sync.Mutex
}

func NewSmartRetry(config RetryConfig) *SmartRetry {
	return &SmartRetry{
		config: config,
		rand:   rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (sr *SmartRetry) Execute(fn func() error) error {
	var lastErr error

	for attempt := 0; attempt <= sr.config.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := sr.calculateDelay(attempt)
			time.Sleep(delay)
		}

		err := fn()
		if err == nil {
			return nil
		}

		lastErr = err

		if !sr.isRetryable(err) {
			break
		}
	}

	return lastErr
}

func (sr *SmartRetry) calculateDelay(attempt int) time.Duration {
	delay := time.Duration(float64(sr.config.BaseDelay) * math.Pow(sr.config.BackoffFactor, float64(attempt-1)))

	if delay > sr.config.MaxDelay {
		delay = sr.config.MaxDelay
	}

	if sr.config.EnableJitter {
		sr.mu.Lock()
		jitter := time.Duration(sr.rand.Float64() * float64(delay) * 0.1)
		sr.mu.Unlock()
		delay += jitter
	}

	return delay
}

func (sr *SmartRetry) isRetryable(err error) bool {
	// Define retryable errors
	retryableErrors := []error{
		context.DeadlineExceeded,
		&net.OpError{},
		&net.DNSError{},
	}

	for _, retryableErr := range retryableErrors {
		if errors.Is(err, retryableErr) {
			return true
		}
	}

	// Check for temporary errors
	if temp, ok := err.(interface{ Temporary() bool }); ok && temp.Temporary() {
		return true
	}

	return false
}

// Buffer Pool for memory optimization
type BufferPool struct {
	pool sync.Pool
	size int
}

func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

func (bp *BufferPool) Get() []byte {
	return bp.pool.Get().([]byte)
}

func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) >= bp.size {
		bp.pool.Put(buf[:bp.size])
	}
}

// Metrics Collection
type TestMetrics struct {
	TotalTests        int64                `json:"total_tests"`
	SuccessfulTests   int64                `json:"successful_tests"`
	FailedTests       int64                `json:"failed_tests"`
	AverageLatency    float64              `json:"average_latency"`
	TestDuration      time.Duration        `json:"test_duration"`
	ErrorDistribution map[string]int64     `json:"error_distribution"`
	MemoryUsage       runtime.MemStats     `json:"memory_usage"`
	ThroughputPerSec  float64              `json:"throughput_per_sec"`
	StartTime         time.Time            `json:"start_time"`
	mu                sync.RWMutex
}

func NewTestMetrics() *TestMetrics {
	return &TestMetrics{
		ErrorDistribution: make(map[string]int64),
		StartTime:         time.Now(),
	}
}

func (tm *TestMetrics) UpdateSuccess(latency float64) {
	atomic.AddInt64(&tm.TotalTests, 1)
	atomic.AddInt64(&tm.SuccessfulTests, 1)

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Update average latency using moving average
	total := atomic.LoadInt64(&tm.SuccessfulTests)
	tm.AverageLatency = (tm.AverageLatency*float64(total-1) + latency) / float64(total)
}

func (tm *TestMetrics) UpdateFailure(errorType string) {
	atomic.AddInt64(&tm.TotalTests, 1)
	atomic.AddInt64(&tm.FailedTests, 1)

	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.ErrorDistribution[errorType]++
}

func (tm *TestMetrics) UpdateMemoryUsage() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	runtime.ReadMemStats(&tm.MemoryUsage)
}

func (tm *TestMetrics) CalculateThroughput() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	elapsed := time.Since(tm.StartTime).Seconds()
	if elapsed > 0 {
		tm.ThroughputPerSec = float64(atomic.LoadInt64(&tm.TotalTests)) / elapsed
	}
}

func (tm *TestMetrics) GetStats() (int64, int64, float64, float64) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	total := atomic.LoadInt64(&tm.TotalTests)
	successful := atomic.LoadInt64(&tm.SuccessfulTests)

	successRate := 0.0
	if total > 0 {
		successRate = float64(successful) / float64(total) * 100
	}

	return total, successful, successRate, tm.AverageLatency
}

// Progress Tracker with ETA calculation
type ProgressTracker struct {
	total     int64
	completed int64
	startTime time.Time
	mu        sync.RWMutex
	lastLog   time.Time
	logInterval time.Duration
}

func NewProgressTracker(total int64) *ProgressTracker {
	return &ProgressTracker{
		total:       total,
		startTime:   time.Now(),
		lastLog:     time.Now(),
		logInterval: 10 * time.Second, // Log every 10 seconds
	}
}

func (pt *ProgressTracker) UpdateProgress(completed int64) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pt.completed = completed

	// Log progress at intervals
	if time.Since(pt.lastLog) >= pt.logInterval {
		pt.logProgress()
		pt.lastLog = time.Now()
	}
}

func (pt *ProgressTracker) IncrementProgress() {
	atomic.AddInt64(&pt.completed, 1)

	// Check if we need to log
	if time.Since(pt.lastLog) >= pt.logInterval {
		pt.UpdateProgress(atomic.LoadInt64(&pt.completed))
	}
}

func (pt *ProgressTracker) logProgress() {
	elapsed := time.Since(pt.startTime)
	rate := float64(pt.completed) / elapsed.Seconds()

	remaining := pt.total - pt.completed
	eta := time.Duration(0)
	if rate > 0 {
		eta = time.Duration(float64(remaining)/rate) * time.Second
	}

	percentage := float64(pt.completed) / float64(pt.total) * 100

	fmt.Printf("Progress: %d/%d (%.1f%%) | Rate: %.1f/s | Elapsed: %s | ETA: %s\n",
		pt.completed, pt.total, percentage, rate, elapsed.Round(time.Second), eta.Round(time.Second))
}

func (pt *ProgressTracker) GetProgress() (int64, int64, float64) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	percentage := float64(pt.completed) / float64(pt.total) * 100
	return pt.completed, pt.total, percentage
}

// Health Checker for system health monitoring
type HealthCheck interface {
	Name() string
	Check() error
}

type HealthChecker struct {
	checks map[string]HealthCheck
	mu     sync.RWMutex
}

func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		checks: make(map[string]HealthCheck),
	}
}

func (hc *HealthChecker) AddCheck(check HealthCheck) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	hc.checks[check.Name()] = check
}

func (hc *HealthChecker) RemoveCheck(name string) {
	hc.mu.Lock()
	defer hc.mu.Unlock()
	delete(hc.checks, name)
}

func (hc *HealthChecker) CheckAll() map[string]error {
	hc.mu.RLock()
	checks := make(map[string]HealthCheck)
	for name, check := range hc.checks {
		checks[name] = check
	}
	hc.mu.RUnlock()

	results := make(map[string]error)
	for name, check := range checks {
		results[name] = check.Check()
	}

	return results
}

// Memory Health Check
type MemoryHealthCheck struct {
	maxMemoryMB int64
}

func NewMemoryHealthCheck(maxMemoryMB int64) *MemoryHealthCheck {
	return &MemoryHealthCheck{maxMemoryMB: maxMemoryMB}
}

func (mhc *MemoryHealthCheck) Name() string {
	return "memory"
}

func (mhc *MemoryHealthCheck) Check() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMemoryMB := int64(m.Alloc / 1024 / 1024)
	if currentMemoryMB > mhc.maxMemoryMB {
		return fmt.Errorf("memory usage too high: %d MB (max: %d MB)", currentMemoryMB, mhc.maxMemoryMB)
	}

	return nil
}

// Disk Space Health Check
type DiskHealthCheck struct {
	path       string
	minSpaceGB int64
}

func NewDiskHealthCheck(path string, minSpaceGB int64) *DiskHealthCheck {
	return &DiskHealthCheck{
		path:       path,
		minSpaceGB: minSpaceGB,
	}
}

func (dhc *DiskHealthCheck) Name() string {
	return "disk_space"
}

func (dhc *DiskHealthCheck) Check() error {
	// This is a simplified check - in a real implementation,
	// you would use platform-specific code to check disk space
	return nil
}

// Adaptive Configuration Manager
type AdaptiveConfig struct {
	successRate    float64
	avgLatency     float64
	memoryUsage    float64
	adjustmentRate float64
	mu             sync.RWMutex
}

func NewAdaptiveConfig() *AdaptiveConfig {
	return &AdaptiveConfig{
		adjustmentRate: 0.1, // 10% adjustment per iteration
	}
}

func (ac *AdaptiveConfig) UpdateMetrics(successRate, avgLatency, memoryUsage float64) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	ac.successRate = successRate
	ac.avgLatency = avgLatency
	ac.memoryUsage = memoryUsage
}

func (ac *AdaptiveConfig) SuggestWorkerCount(current int) int {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	// Increase workers if success rate is high and latency is low
	if ac.successRate > 80 && ac.avgLatency < 3000 && ac.memoryUsage < 80 {
		adjustment := int(float64(current) * ac.adjustmentRate)
		return current + max(1, adjustment)
	}

	// Decrease workers if success rate is low or latency is high
	if ac.successRate < 50 || ac.avgLatency > 10000 || ac.memoryUsage > 90 {
		adjustment := int(float64(current) * ac.adjustmentRate)
		return max(1, current-max(1, adjustment))
	}

	return current
}

func (ac *AdaptiveConfig) SuggestBatchSize(current int) int {
	ac.mu.RLock()
	defer ac.mu.RUnlock()

	// Similar logic for batch size optimization
	if ac.successRate > 80 && ac.memoryUsage < 70 {
		adjustment := int(float64(current) * ac.adjustmentRate)
		return current + max(10, adjustment)
	}

	if ac.successRate < 40 || ac.memoryUsage > 85 {
		adjustment := int(float64(current) * ac.adjustmentRate)
		return max(10, current-max(10, adjustment))
	}

	return current
}

// Utility functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Graceful Shutdown Manager
type GracefulShutdown struct {
	shutdownChan chan bool
	timeout      time.Duration
	cleanupFuncs []func() error
	mu           sync.Mutex
}

func NewGracefulShutdown(timeout time.Duration) *GracefulShutdown {
	return &GracefulShutdown{
		shutdownChan: make(chan bool, 1),
		timeout:      timeout,
		cleanupFuncs: make([]func() error, 0),
	}
}

func (gs *GracefulShutdown) AddCleanupFunc(cleanup func() error) {
	gs.mu.Lock()
	defer gs.mu.Unlock()
	gs.cleanupFuncs = append(gs.cleanupFuncs, cleanup)
}

func (gs *GracefulShutdown) Shutdown() error {
	gs.shutdownChan <- true

	ctx, cancel := context.WithTimeout(context.Background(), gs.timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- gs.runCleanup()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("cleanup timeout after %v", gs.timeout)
	}
}

func (gs *GracefulShutdown) runCleanup() error {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	for i, cleanup := range gs.cleanupFuncs {
		if err := cleanup(); err != nil {
			return fmt.Errorf("cleanup function %d failed: %w", i, err)
		}
	}

	return nil
}

func (gs *GracefulShutdown) WaitForShutdown() {
	<-gs.shutdownChan
}
