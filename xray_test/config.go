package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	ProxyTester   ProxyTesterConfig   `yaml:"proxy_tester"`
	QualityTester QualityTesterConfig `yaml:"quality_tester"`
	Common        CommonConfig        `yaml:"common"`
	Logging       LoggingConfig       `yaml:"logging"`
	Performance   PerformanceConfig   `yaml:"performance"`
}

// ProxyTesterConfig configuration for proxy testing
type ProxyTesterConfig struct {
	MaxWorkers      int           `yaml:"max_workers" env:"PROXY_MAX_WORKERS" default:"300"`
	Timeout         time.Duration `yaml:"timeout" env:"PROXY_TIMEOUT" default:"5s"`
	BatchSize       int           `yaml:"batch_size" env:"PROXY_BATCH_SIZE" default:"300"`
	XrayPath        string        `yaml:"xray_path" env:"XRAY_PATH" default:""`
	IncrementalSave bool          `yaml:"incremental_save" env:"INCREMENTAL_SAVE" default:"true"`
	PortRange       PortRange     `yaml:"port_range"`
	RetryConfig     RetryConfig   `yaml:"retry"`
}

// QualityTesterConfig configuration for quality testing
type QualityTesterConfig struct {
	MaxConfigs         int           `yaml:"max_configs" env:"QUALITY_MAX_CONFIGS" default:"10000"`
	Concurrent         int           `yaml:"concurrent" env:"QUALITY_CONCURRENT" default:"8"`
	TestTimeout        time.Duration `yaml:"test_timeout" env:"QUALITY_TIMEOUT" default:"120s"`
	StabilityThreshold float64       `yaml:"stability_threshold" env:"STABILITY_THRESHOLD" default:"0.75"`
	CriticalSiteWeight float64       `yaml:"critical_site_weight" default:"0.5"`
	LatencyWeight      float64       `yaml:"latency_weight" default:"0.25"`
	StabilityWeight    float64       `yaml:"stability_weight" default:"0.15"`
	SpeedWeight        float64       `yaml:"speed_weight" default:"0.1"`
	AdaptiveTesting    bool          `yaml:"adaptive_testing" default:"true"`
}

// CommonConfig shared configuration
type CommonConfig struct {
	OutputDir     string        `yaml:"output_dir" env:"OUTPUT_DIR" default:"../data"`
	TempDir       string        `yaml:"temp_dir" env:"TEMP_DIR" default:"./temp"`
	MaxFileSize   int64         `yaml:"max_file_size" default:"104857600"` // 100MB
	CleanupAfter  time.Duration `yaml:"cleanup_after" default:"1h"`
	EnableMetrics bool          `yaml:"enable_metrics" default:"true"`
}

// LoggingConfig logging configuration
type LoggingConfig struct {
	Level      string `yaml:"level" env:"LOG_LEVEL" default:"info"`
	Format     string `yaml:"format" default:"text"`
	OutputFile string `yaml:"output_file" env:"LOG_FILE"`
	MaxSize    int    `yaml:"max_size" default:"100"`     // MB
	MaxBackups int    `yaml:"max_backups" default:"3"`
	MaxAge     int    `yaml:"max_age" default:"28"`       // days
	Compress   bool   `yaml:"compress" default:"true"`
}

// PerformanceConfig performance optimization settings
type PerformanceConfig struct {
	EnableConnectionPool bool          `yaml:"enable_connection_pool" default:"true"`
	PoolSize            int           `yaml:"pool_size" default:"100"`
	PoolTimeout         time.Duration `yaml:"pool_timeout" default:"30s"`
	EnableCircuitBreaker bool          `yaml:"enable_circuit_breaker" default:"true"`
	CircuitBreakerConfig CircuitBreakerConfig `yaml:"circuit_breaker"`
	RateLimitConfig     RateLimitConfig      `yaml:"rate_limit"`
	MemoryOptimization  MemoryOptimization   `yaml:"memory_optimization"`
}

// PortRange configuration for port management
type PortRange struct {
	Start int `yaml:"start" default:"10000"`
	End   int `yaml:"end" default:"20000"`
}

// RetryConfig retry configuration
type RetryConfig struct {
	MaxRetries    int           `yaml:"max_retries" default:"3"`
	BaseDelay     time.Duration `yaml:"base_delay" default:"1s"`
	MaxDelay      time.Duration `yaml:"max_delay" default:"30s"`
	BackoffFactor float64       `yaml:"backoff_factor" default:"2.0"`
	EnableJitter  bool          `yaml:"enable_jitter" default:"true"`
}

// CircuitBreakerConfig circuit breaker configuration
type CircuitBreakerConfig struct {
	MaxFailures   int           `yaml:"max_failures" default:"5"`
	Timeout       time.Duration `yaml:"timeout" default:"60s"`
	ResetTimeout  time.Duration `yaml:"reset_timeout" default:"30s"`
	ThresholdRate float64       `yaml:"threshold_rate" default:"0.5"`
}

// RateLimitConfig rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool          `yaml:"enabled" default:"true"`
	RequestsPerSec int           `yaml:"requests_per_sec" default:"10"`
	BurstSize      int           `yaml:"burst_size" default:"20"`
	CleanupPeriod  time.Duration `yaml:"cleanup_period" default:"1m"`
}

// MemoryOptimization memory optimization settings
type MemoryOptimization struct {
	EnableBufferPool   bool `yaml:"enable_buffer_pool" default:"true"`
	BufferSize         int  `yaml:"buffer_size" default:"32768"` // 32KB
	MaxBuffers         int  `yaml:"max_buffers" default:"1000"`
	EnableGCOptimization bool `yaml:"enable_gc_optimization" default:"true"`
	GCPercent          int  `yaml:"gc_percent" default:"100"`
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	config := &Config{}

	// Set defaults
	if err := setDefaults(config); err != nil {
		return nil, fmt.Errorf("failed to set defaults: %w", err)
	}

	// Load from file if exists
	if configPath != "" {
		if _, err := os.Stat(configPath); err == nil {
			data, err := os.ReadFile(configPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}

			if err := yaml.Unmarshal(data, config); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables
	if err := loadFromEnv(config); err != nil {
		return nil, fmt.Errorf("failed to load from environment: %w", err)
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// setDefaults sets default values for configuration
func setDefaults(config *Config) error {
	// ProxyTester defaults
	config.ProxyTester.MaxWorkers = 300
	config.ProxyTester.Timeout = 5 * time.Second
	config.ProxyTester.BatchSize = 300
	config.ProxyTester.XrayPath = ""  // Will be auto-detected by findXrayExecutable()
	config.ProxyTester.IncrementalSave = true
	config.ProxyTester.PortRange.Start = 10000
	config.ProxyTester.PortRange.End = 20000
	config.ProxyTester.RetryConfig.MaxRetries = 3
	config.ProxyTester.RetryConfig.BaseDelay = 1 * time.Second
	config.ProxyTester.RetryConfig.MaxDelay = 30 * time.Second
	config.ProxyTester.RetryConfig.BackoffFactor = 2.0
	config.ProxyTester.RetryConfig.EnableJitter = true

	// QualityTester defaults
	config.QualityTester.MaxConfigs = 10000
	config.QualityTester.Concurrent = 8
	config.QualityTester.TestTimeout = 120 * time.Second
	config.QualityTester.StabilityThreshold = 0.75
	config.QualityTester.CriticalSiteWeight = 0.5
	config.QualityTester.LatencyWeight = 0.25
	config.QualityTester.StabilityWeight = 0.15
	config.QualityTester.SpeedWeight = 0.1
	config.QualityTester.AdaptiveTesting = true

	// Common defaults
	config.Common.OutputDir = "../data"
	config.Common.TempDir = "./temp"
	config.Common.MaxFileSize = 104857600 // 100MB
	config.Common.CleanupAfter = 1 * time.Hour
	config.Common.EnableMetrics = true

	// Logging defaults
	config.Logging.Level = "info"
	config.Logging.Format = "text"
	config.Logging.MaxSize = 100
	config.Logging.MaxBackups = 3
	config.Logging.MaxAge = 28
	config.Logging.Compress = true

	// Performance defaults
	config.Performance.EnableConnectionPool = true
	config.Performance.PoolSize = 100
	config.Performance.PoolTimeout = 30 * time.Second
	config.Performance.EnableCircuitBreaker = true
	config.Performance.CircuitBreakerConfig.MaxFailures = 5
	config.Performance.CircuitBreakerConfig.Timeout = 60 * time.Second
	config.Performance.CircuitBreakerConfig.ResetTimeout = 30 * time.Second
	config.Performance.CircuitBreakerConfig.ThresholdRate = 0.5
	config.Performance.RateLimitConfig.Enabled = true
	config.Performance.RateLimitConfig.RequestsPerSec = 10
	config.Performance.RateLimitConfig.BurstSize = 20
	config.Performance.RateLimitConfig.CleanupPeriod = 1 * time.Minute
	config.Performance.MemoryOptimization.EnableBufferPool = true
	config.Performance.MemoryOptimization.BufferSize = 32768
	config.Performance.MemoryOptimization.MaxBuffers = 1000
	config.Performance.MemoryOptimization.EnableGCOptimization = true
	config.Performance.MemoryOptimization.GCPercent = 100

	return nil
}

// loadFromEnv loads configuration from environment variables
func loadFromEnv(config *Config) error {
	// ProxyTester environment variables
	if val := os.Getenv("PROXY_MAX_WORKERS"); val != "" {
		if workers, err := strconv.Atoi(val); err == nil {
			config.ProxyTester.MaxWorkers = workers
		}
	}

	if val := os.Getenv("PROXY_TIMEOUT"); val != "" {
		if timeout, err := time.ParseDuration(val); err == nil {
			config.ProxyTester.Timeout = timeout
		}
	}

	if val := os.Getenv("PROXY_BATCH_SIZE"); val != "" {
		if batch, err := strconv.Atoi(val); err == nil {
			config.ProxyTester.BatchSize = batch
		}
	}

	if val := os.Getenv("XRAY_PATH"); val != "" {
		config.ProxyTester.XrayPath = val
	}

	if val := os.Getenv("INCREMENTAL_SAVE"); val != "" {
		if save, err := strconv.ParseBool(val); err == nil {
			config.ProxyTester.IncrementalSave = save
		}
	}

	// QualityTester environment variables
	if val := os.Getenv("QUALITY_MAX_CONFIGS"); val != "" {
		if configs, err := strconv.Atoi(val); err == nil {
			config.QualityTester.MaxConfigs = configs
		}
	}

	if val := os.Getenv("QUALITY_CONCURRENT"); val != "" {
		if concurrent, err := strconv.Atoi(val); err == nil {
			config.QualityTester.Concurrent = concurrent
		}
	}

	if val := os.Getenv("QUALITY_TIMEOUT"); val != "" {
		if timeout, err := time.ParseDuration(val); err == nil {
			config.QualityTester.TestTimeout = timeout
		}
	}

	if val := os.Getenv("STABILITY_THRESHOLD"); val != "" {
		if threshold, err := strconv.ParseFloat(val, 64); err == nil {
			config.QualityTester.StabilityThreshold = threshold
		}
	}

	// Common environment variables
	if val := os.Getenv("OUTPUT_DIR"); val != "" {
		config.Common.OutputDir = val
	}

	if val := os.Getenv("TEMP_DIR"); val != "" {
		config.Common.TempDir = val
	}

	if val := os.Getenv("LOG_LEVEL"); val != "" {
		config.Logging.Level = val
	}

	if val := os.Getenv("LOG_FILE"); val != "" {
		config.Logging.OutputFile = val
	}

	return nil
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate port range
	if config.ProxyTester.PortRange.Start >= config.ProxyTester.PortRange.End {
		return fmt.Errorf("invalid port range: start (%d) must be less than end (%d)", 
			config.ProxyTester.PortRange.Start, config.ProxyTester.PortRange.End)
	}

	if config.ProxyTester.PortRange.Start < 1 || config.ProxyTester.PortRange.End > 65535 {
		return fmt.Errorf("port range must be between 1 and 65535")
	}

	// Validate workers and concurrency
	if config.ProxyTester.MaxWorkers < 1 {
		return fmt.Errorf("max_workers must be at least 1")
	}

	if config.QualityTester.Concurrent < 1 {
		return fmt.Errorf("concurrent must be at least 1")
	}

	// Validate timeouts
	if config.ProxyTester.Timeout < time.Second {
		return fmt.Errorf("proxy timeout must be at least 1 second")
	}

	if config.QualityTester.TestTimeout < time.Second {
		return fmt.Errorf("quality test timeout must be at least 1 second")
	}

	// Validate weights (should sum to approximately 1.0)
	totalWeight := config.QualityTester.CriticalSiteWeight + 
		config.QualityTester.LatencyWeight + 
		config.QualityTester.StabilityWeight + 
		config.QualityTester.SpeedWeight

	if totalWeight < 0.9 || totalWeight > 1.1 {
		return fmt.Errorf("quality test weights should sum to approximately 1.0, got %.2f", totalWeight)
	}

	// Validate stability threshold
	if config.QualityTester.StabilityThreshold < 0 || config.QualityTester.StabilityThreshold > 1 {
		return fmt.Errorf("stability threshold must be between 0 and 1")
	}

	// Validate logging level
	validLogLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	if !validLogLevels[config.Logging.Level] {
		return fmt.Errorf("invalid log level: %s", config.Logging.Level)
	}

	return nil
}

// SaveConfig saves configuration to a YAML file
func SaveConfig(config *Config, filePath string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetDefaultConfig returns a configuration with default values
func GetDefaultConfig() *Config {
	config := &Config{}
	setDefaults(config)
	return config
}
