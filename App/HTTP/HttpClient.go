// Package HttpClient wraps HTTP GET requests and detects bot protection challenges.
package HttpClient

import (
	"Engine-AntiGinx/App/Detection"
	"bytes"
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
type HttpError struct {
	Url         string   // The URL that caused the Error
	Code        int      // Error Code for categorization
	Message     string   // Human-readable Error description
	Error       any      // Original Error object or response
	IsRetryable bool     // Check if error is retryable
	Protections []string // Vendor-identified bot protections, if any
}

type httpWrapperConfig struct {
	headers          map[string]string // Custom HTTP headers to be sent with requests
	antiBotDetection bool              // Enable anti-bot detection bypass features
}

// WrapperOption is a functional option type for configuring the HTTP wrapper.
type WrapperOption func(*httpWrapperConfig)

func defaultHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "AntiGinx/1.0",
	}
}

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

// WithHeaders adds or overrides configured headers (use at wrapper construction).
func WithHeaders(h map[string]string) WrapperOption {
	return func(cfg *httpWrapperConfig) {
		for k, v := range h {
			cfg.headers[k] = v // override or add new key
		}
	}
}

// WithAntiBotDetection adds browser-like headers and enables optional client settings.
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

type httpWrapper struct {
	client *http.Client      // Underlying HTTP client
	config httpWrapperConfig // Wrapper configuration including headers and settings
}

// CreateHttpWrapper creates a new HTTP wrapper instance with optional configuration.
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

// Get performs an HTTP GET and panics with HttpError on failure or a blocking challenge.
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

	// The body is read before the status is judged so that protection detection can
	// inspect a challenge page's markup, which is where the strongest evidence lives.
	body, err := io.ReadAll(resp.Body)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			fmt.Printf("HttpClient \nWarning: Failed to close response channel: %s", err.Error())
		}
	}()
	if err != nil {
		panic(HttpError{
			Url:         url,
			Code:        200,
			Message:     "Error reading response body: " + err.Error(),
			Error:       err,
			IsRetryable: false,
		})
	}
	// Reset the body so downstream tests can read it
	resp.Body = io.NopCloser(bytes.NewReader(body))

	report := Detection.FromResponse(resp, string(body))

	// Handle HTTP Error status codes
	if resp.StatusCode != 200 {
		message := "HTTP Status Code not 200 (OK): " + strconv.Itoa(resp.StatusCode)
		if report.HasProtection() {
			message += "\nBot protection detected:\n" + Detection.FormatList(report.All())
		}
		panic(HttpError{
			Url:         url,
			Code:        102,
			Message:     message,
			Error:       resp,
			IsRetryable: false,
			Protections: report.All(),
		})
	}

	// A 200 response carries the target's own content, so a protection layer in front of
	// it is not a reason to stop: CDN fingerprints such as CF-RAY or CF-Cache-Status are
	// present on every proxied site, healthy ones included. Reporting that layer is the
	// bot-protection test's job. Only an interstitial served with a 200 status actually
	// withholds the content the response tests came for.
	if report.IsBlocked() && !cfg.antiBotDetection {
		panic(HttpError{
			Url:         url,
			Code:        300,
			Message:     "Bot protection challenge served instead of content:\n" + Detection.FormatList(report.Challenge),
			Error:       resp,
			IsRetryable: false,
			Protections: report.All(),
		})
	}

	return resp
}
