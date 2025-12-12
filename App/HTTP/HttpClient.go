// Package HttpClient provides an advanced HTTP client wrapper with bot protection detection
// and anti-detection capabilities. It wraps Go's standard http.Client with additional features
// including Cloudflare detection, stealth headers, TLS fingerprint masking, and human-like behavior simulation.
//
// The package supports multiple protection levels and can be configured to bypass common bot
// detection mechanisms while maintaining legitimate scanning capabilities.
package HttpClient

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"time"
)

// HttpError represents an HTTP-related Error with structured information for debugging.
// It is used internally for panic-based Error handling throughout the HTTP client operations.
//
// Error codes:
//   - 100: Request creation Error
//   - 101: Network Error (DNS, timeout, connection issues)
//   - 102: HTTP status Error (non-200 responses)
//   - 200: Response body reading Error
//   - 300: Bot protection detected
type HttpError struct {
	Url         string // The URL that caused the Error
	Code        int    // Error Code for categorization
	Message     string // Human-readable Error description
	Error       any    // Original Error object or response
	IsRetryable bool   // Check if error is retryable
}

// httpWrapperConfig holds the configuration for the HTTP wrapper including custom headers
// and anti-bot detection settings. This structure is modified by WrapperOption functions
// to customize client behavior.
type httpWrapperConfig struct {
	headers          map[string]string // Custom HTTP headers to be sent with requests
	antiBotDetection bool              // Enable anti-bot detection bypass features
}

// WrapperOption is a functional option type for configuring the HTTP wrapper.
// It allows flexible, composable configuration through functions like WithHeaders and WithAntiBotDetection.
type WrapperOption func(*httpWrapperConfig)

// defaultHeaders returns the default HTTP headers used by the AntiGinx scanner.
// These headers identify the client as AntiGinx/1.0 for legitimate scanning purposes.
//
// Returns:
//   - map[string]string: Default headers with User-Agent set to "AntiGinx/1.0"
func defaultHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "AntiGinx/1.0",
	}
}

// getAntiDetectionHeaders returns comprehensive browser headers with maximum stealth capabilities.
// This function provides the best security by including all browser characteristics, client hints,
// viewport information, device capabilities, and network conditions that match a real Chrome browser.
//
// Includes enhanced features for maximum protection:
//   - Full Chrome client hints (viewport, DPR, device memory, architecture)
//   - Browser feature detection headers (Save-Data, RTT, ECT, Downlink)
//   - Color scheme and motion preferences
//   - Complete platform and architecture information
//   - Security fetch metadata and all standard browser headers
//
// Returns:
//   - map[string]string: Comprehensive headers for maximum anti-detection protection
func getAntiDetectionHeaders() map[string]string {
	return map[string]string{
		"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Language":           "en-US,en;q=0.9,pl;q=0.8",
		"Accept-Encoding":           "gzip, deflate, br",
		"DNT":                       "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"sec-ch-ua":                 `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`,
		"sec-ch-ua-mobile":          "?0",
		"sec-ch-ua-platform":        `"Windows"`,
		"Cache-Control":             "max-age=0",
		"Pragma":                    "no-cache",
		"Sec-GPC":                   "1",
		// Enhanced client hints (matching real Chrome browser)
		"sec-ch-viewport-width":      "1920",
		"sec-ch-viewport-height":     "1080",
		"sec-ch-dpr":                 "1",
		"sec-ch-device-memory":       "8",
		"sec-ch-ua-arch":             `"x86"`,
		"sec-ch-ua-bitness":          `"64"`,
		"sec-ch-ua-full-version":     `"120.0.6099.109"`,
		"sec-ch-ua-model":            `""`,
		"sec-ch-ua-platform-version": `"15.0.0"`,
		"sec-ch-ua-wow64":            "?0",
		// Additional stealth headers
		"sec-ch-prefers-color-scheme":   "light",
		"sec-ch-prefers-reduced-motion": "no-preference",
		"Viewport-Width":                "1920",
		"Width":                         "1920",
		// Browser feature detection headers
		"Save-Data":     "0",
		"Device-Memory": "8",
		"RTT":           "100",
		"Downlink":      "10",
		"ECT":           "4g",
	}
}

// getRandomUserAgent returns a random realistic user agent from a pool of current browser versions.
// This helps avoid fingerprinting by varying the user agent across requests, simulating
// traffic from different browsers and operating systems.
//
// Includes user agents for:
//   - Chrome on Windows, macOS, and Linux
//   - Firefox on Windows, macOS, and Linux
//   - Safari on macOS
//   - Edge on Windows
//
// Returns:
//   - string: A randomly selected user agent string
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
	return userAgents[rand.Intn(len(userAgents))]
}

// getBrowserTLSConfig returns a TLS configuration that mimics real browser behavior
// including cipher suites, curve preferences, and protocol versions that match Chrome/Firefox.
// This helps avoid TLS fingerprinting which is used by advanced bot detection systems.
//
// Configuration includes:
//   - TLS 1.2 and 1.3 support
//   - Modern cipher suites (AES-GCM, ChaCha20-Poly1305)
//   - Realistic curve preferences (X25519, P-256, P-384)
//   - HTTP/2 and HTTP/1.1 ALPN support
//
// Returns:
//   - *tls.Config: Browser-like TLS configuration
func getBrowserTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// WithHeaders creates a WrapperOption that adds or overrides HTTP headers in the client configuration.
// This option can be used both when creating the wrapper and on individual requests.
//
// Headers provided through this option will merge with existing headers, with new values
// overriding existing ones for the same header name.
//
// Parameters:
//   - h: Map of header names to values
//
// Returns:
//   - WrapperOption: Configuration function that applies the headers
//
// Example:
//
//	wrapper := CreateHttpWrapper(WithHeaders(map[string]string{
//	    "Authorization": "Bearer token123",
//	    "Custom-Header": "value",
//	}))
func WithHeaders(h map[string]string) WrapperOption {
	return func(cfg *httpWrapperConfig) {
		for k, v := range h {
			cfg.headers[k] = v // override or add new key
		}
	}
}

// WithAntiBotDetection enables comprehensive anti-bot detection bypass with maximum protection.
// This option activates all available techniques including realistic headers, TLS fingerprint masking,
// cookie handling, random delays, and header ordering.
//
// When enabled, the client will:
//   - Use browser-like TLS configuration
//   - Maintain cookie jar for session handling
//   - Add realistic delays between requests (1-3 seconds)
//   - Randomize user agents
//   - Order headers like real browsers
//   - Support HTTP/2
//   - Use advanced stealth headers with all client hints and browser characteristics
//
// Returns:
//   - WrapperOption: Configuration function that enables anti-bot detection features
//
// Example:
//
//	wrapper := CreateHttpWrapper(WithAntiBotDetection())
func WithAntiBotDetection() WrapperOption {
	return func(cfg *httpWrapperConfig) {
		cfg.antiBotDetection = true

		// Always use maximum protection with comprehensive anti-detection headers
		headers := getAntiDetectionHeaders()

		// Apply headers
		for k, v := range headers {
			if _, exists := cfg.headers[k]; !exists {
				cfg.headers[k] = v
			}
		}
	}
}

// httpWrapper wraps Go's standard http.Client with additional bot protection detection
// and anti-detection capabilities. It provides a higher-level interface for making
// HTTP requests while handling common security scanning challenges.
type httpWrapper struct {
	client *http.Client      // Underlying HTTP client
	config httpWrapperConfig // Wrapper configuration including headers and settings
}

// CreateHttpWrapper creates a new HTTP wrapper instance with optional configuration.
// The wrapper can be configured with custom headers, anti-bot detection features,
// and other options through functional options.
//
// By default, the wrapper uses:
//   - Default AntiGinx user agent
//   - 30-second timeout
//   - Standard HTTP transport
//
// When anti-bot detection is enabled, it additionally configures:
//   - Browser-like TLS configuration
//   - HTTP/2 support
//   - Cookie jar for session management
//   - Connection pooling
//
// Parameters:
//   - opts: Variable number of WrapperOption functions for configuration
//
// Returns:
//   - *httpWrapper: Configured HTTP wrapper ready for use
//
// Example:
//
//	// Basic wrapper
//	wrapper := CreateHttpWrapper()
//
//	// Wrapper with custom headers
//	wrapper := CreateHttpWrapper(WithHeaders(map[string]string{
//	    "Authorization": "Bearer token",
//	}))
//
//	// Wrapper with stealth mode
//	wrapper := CreateHttpWrapper(WithAntiBotDetection("advanced"))
func CreateHttpWrapper(opts ...WrapperOption) *httpWrapper {
	cfg := httpWrapperConfig{
		headers:          defaultHeaders(),
		antiBotDetection: false,
	}

	// apply optional config
	for _, opt := range opts {
		opt(&cfg)
	}

	// Create transport with advanced configuration
	transport := &http.Transport{}

	// Configure TLS and other settings if anti-bot detection is enabled
	if cfg.antiBotDetection {
		transport.TLSClientConfig = getBrowserTLSConfig()

		// Configure for HTTP/2 support like real browsers
		transport.ForceAttemptHTTP2 = true
		transport.MaxIdleConns = 100
		transport.MaxIdleConnsPerHost = 10
		transport.IdleConnTimeout = 90 * time.Second
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Add cookie jar if anti-bot detection is enabled
	if cfg.antiBotDetection {
		if jar, err := cookiejar.New(nil); err == nil {
			client.Jar = jar
		}
	}

	return &httpWrapper{
		client: client,
		config: cfg,
	}
}

// Get performs an HTTP GET request with built-in bot protection detection and Error handling.
// This method implements comprehensive security scanning capabilities including detection of
// Cloudflare, CAPTCHA, and various bot protection mechanisms.
//
// The method supports per-request configuration overrides and includes:
//   - Automatic bot protection detection (Cloudflare, Incapsula, DataDome, etc.)
//   - Human-like behavior simulation when anti-bot detection is enabled
//   - Structured Error handling with panic-based Error reporting
//   - Response body validation
//
// Error handling:
// The method panics with HttpError containing structured Error information:
//   - Code 100: Request creation failed
//   - Code 101: Network Error (DNS, timeout, connection)
//   - Code 102: Non-200 HTTP status Code
//   - Code 200: Response body reading Error
//   - Code 300: Bot protection detected (only in strict mode)
//
// Bot protection detection includes:
//   - Header-based: Cloudflare Server, CF-RAY, CF-Cache-Status, CF-CHL-BCODE
//   - Service detection: Incapsula, Distil Networks, PerimeterX, DataDome, Reblaze, Radware
//   - Content-based: CAPTCHA, challenge pages, access denied messages, JavaScript requirements
//
// Parameters:
//   - Url: Target URL to request
//   - opts: Optional per-request configuration overrides
//
// Returns:
//   - *http.Response: HTTP response object (only if successful and no bot protection detected)
//
// Panics:
//   - HttpError: On any Error condition with detailed Error information
//
// Example:
//
//	wrapper := CreateHttpWrapper()
//	response := wrapper.Get("https://example.com")
//	fmt.Printf("Status: %s\n", response.Status)
//
//	// With per-request options
//	response := wrapper.Get("https://api.example.com", WithHeaders(map[string]string{
//	    "Accept": "application/json",
//	}))
func (hw *httpWrapper) Get(url string, opts ...WrapperOption) *http.Response {
	// Start with wrapper's base config
	cfg := hw.config

	// Apply per-call overrides
	for _, opt := range opts {
		opt(&cfg)
	}

	// Apply request delay for human-like behavior if anti-bot detection is enabled
	if cfg.antiBotDetection {
		delay := time.Duration(rand.Intn(2000)+1000) * time.Millisecond // 1-3 second delay
		time.Sleep(delay)
	}

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(HttpError{
			Url:         url,
			Code:        100,
			Message:     "Failed to create HTTP request: " + err.Error(),
			Error:       err,
			IsRetryable: false,
		})
	}

	// Use random user agent if anti-bot detection is enabled
	headers := hw.config.headers
	if cfg.antiBotDetection {
		headers = make(map[string]string)
		for k, v := range hw.config.headers {
			headers[k] = v
		}
		headers["User-Agent"] = getRandomUserAgent()
	}

	// Add headers in browser-like order only if anti-bot detection is enabled
	if cfg.antiBotDetection {
		browserHeaderOrder := []string{
			"Host",
			"Connection",
			"Cache-Control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"Upgrade-Insecure-Requests",
			"User-Agent",
			"Accept",
			"Sec-Fetch-Site",
			"Sec-Fetch-Mode",
			"Sec-Fetch-User",
			"Sec-Fetch-Dest",
			"Accept-Encoding",
			"Accept-Language",
		}

		// Set headers in realistic browser order
		for _, headerName := range browserHeaderOrder {
			if value, exists := headers[headerName]; exists {
				req.Header.Set(headerName, value)
			}
		}

		// Add any remaining headers
		for key, value := range headers {
			if req.Header.Get(key) == "" {
				req.Header.Set(key, value)
			}
		}
	} else {
		// Simple header addition when anti-bot detection is disabled
		for key, value := range headers {
			req.Header.Set(key, value)
		}
	}

	// Set Host header explicitly (browsers do this)
	if req.URL.Host != "" {
		req.Header.Set("Host", req.URL.Host)
	}

	// Execute the request
	resp, err := hw.client.Do(req)

	// Network Error
	if err != nil {
		panic(HttpError{
			Url:  url,
			Code: 101,
			Message: `Network Error occurred. This could be due to:
				- DNS lookup failures
				- Connection timeouts
				- Network unreachable
				- No response object exists (resp == nil)`,
			Error:       err,
			IsRetryable: true,
		})
	}

	defer resp.Body.Close()

	// Handle HTTP Error status codes
	if resp.StatusCode != 200 {
		panic(HttpError{
			Url:         url,
			Code:        102,
			Message:     "HTTP Status Code not 200 (OK): " + strconv.Itoa(resp.StatusCode),
			Error:       resp,
			IsRetryable: false,
		})
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(HttpError{
			Url:         url,
			Code:        200,
			Message:     "Error reading response body: " + err.Error(),
			Error:       err,
			IsRetryable: false,
		})
	}

	// Enhanced bot protection detection
	bodyStr := string(body)
	var detectedProtections []string

	// Check for Cloudflare headers and challenges
	if resp.Header.Get("Server") == "cloudflare" {
		detectedProtections = append(detectedProtections, "Cloudflare Server")
	}
	if resp.Header.Get("CF-RAY") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Ray ID: "+resp.Header.Get("CF-RAY"))
	}
	if resp.Header.Get("CF-Cache-Status") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Cache: "+resp.Header.Get("CF-Cache-Status"))
	}
	if resp.Header.Get("CF-CHL-BCODE") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Challenge")
	}

	// Check for various bot protection services
	protectionIndicators := map[string]string{
		"cf-browser-verification": "Cloudflare Browser Verification",
		"__cf_bm":                 "Cloudflare Bot Management",
		"incapsula":               "Incapsula Protection",
		"distil":                  "Distil Networks",
		"perimeterx":              "PerimeterX",
		"datadome":                "DataDome",
		"reblaze":                 "Reblaze",
		"radware":                 "Radware",
	}

	for indicator, service := range protectionIndicators {
		if helpers.ContainsAnySubstring(bodyStr, []string{indicator}) {
			detectedProtections = append(detectedProtections, service+" detected")
		}
	}

	// Enhanced content-based detection
	challengeKeywords := []string{
		"cloudflare", "captcha", "Attention Required", "challenge",
		"verify you are human", "security check", "DDoS protection",
		"Access denied", "blocked", "suspicious activity",
		"bot detected", "automated traffic", "rate limited",
		"javascript is required", "browser check",
	}

	for _, keyword := range challengeKeywords {
		if helpers.ContainsAnySubstring(bodyStr, []string{keyword}) {
			detectedProtections = append(detectedProtections, "Content contains: "+keyword)
		}
	}

	// Only panic if not using anti-bot detection (in strict mode)
	if len(detectedProtections) > 0 && !cfg.antiBotDetection {
		detectionMsg := "Bot protection detected:\n"
		for i, detection := range detectedProtections {
			detectionMsg += fmt.Sprintf("  %d. %s\n", i+1, detection)
		}

		panic(HttpError{
			Url:         url,
			Code:        300,
			Message:     detectionMsg,
			Error:       resp,
			IsRetryable: false,
		})
	}

	return resp
}
