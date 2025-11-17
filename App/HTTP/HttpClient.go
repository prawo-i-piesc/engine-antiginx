package HttpClient

import (
	helpers "Engine-AntiGinx/App/Helpers"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

type httpError struct {
	url     string
	code    int
	message string
	error   any
}

// Customizable HTTP wrapper configuration
type httpWrapperConfig struct {
	headers map[string]string
}

type WrapperOption func(*httpWrapperConfig)

func defaultHeaders() map[string]string {
	return map[string]string{
		"User-Agent": "AntiGinx/1.0",
	}
}

func WithHeaders(h map[string]string) WrapperOption {
	return func(cfg *httpWrapperConfig) {
		for k, v := range h {
			cfg.headers[k] = v // override or add new key
		}
	}
}

// HTTP wrapper struct

type httpWrapper struct {
	client *http.Client
	config httpWrapperConfig
}

func CreateHttpWrapper(opts ...WrapperOption) *httpWrapper {
	cfg := httpWrapperConfig{
		headers: defaultHeaders(),
	}

	// apply optional config
	for _, opt := range opts {
		opt(&cfg)
	}

	return &httpWrapper{
		client: &http.Client{},
		config: cfg,
	}
}

func (hw *httpWrapper) Get(url string, opts ...WrapperOption) *http.Response {
	// Start with wrapper's base config
	cfg := hw.config

	// Apply per-call overrides
	for _, opt := range opts {
		opt(&cfg)
	}

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		panic(httpError{
			url:     url,
			code:    100,
			message: "Failed to create HTTP request: " + err.Error(),
			error:   err,
		})
	}

	// Add headers to the request
	for key, value := range hw.config.headers {
		req.Header.Set(key, value)
	}

	// Execute the request
	resp, err := hw.client.Do(req)

	// Network error
	if err != nil {
		panic(httpError{
			url:  url,
			code: 101,
			message: `Network error occurred. This could be due to:
				- DNS lookup failures
				- Connection timeouts
				- Network unreachable
				- No response object exists (resp == nil)`,
			error: err,
		})
	}

	defer resp.Body.Close() // Ensuring to close the body stream after function finishes (due to defer keyword)

	// Handle HTTP error status codes
	// Futrher logic could be expanded
	if resp.StatusCode != 200 {
		panic(httpError{
			url:     url,
			code:    102,
			message: "HTTP Status code not 200 (OK): " + strconv.Itoa(resp.StatusCode),
			error:   resp,
		})
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(httpError{
			url:     url,
			code:    200,
			message: "Error reading response body: " + err.Error(),
			error:   err,
		})
	}

	// Bot protection detection (Cloudflare, Captcha, etc.)
	bodyStr := string(body)
	var detectedProtections []string

	// Check for Cloudflare headers
	if resp.Header.Get("Server") == "cloudflare" {
		detectedProtections = append(detectedProtections, "Cloudflare Server")
	}
	if resp.Header.Get("CF-RAY") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Ray ID: "+resp.Header.Get("CF-RAY"))
	}
	if resp.Header.Get("CF-CHL-BCODE") != "" {
		detectedProtections = append(detectedProtections, "Cloudflare Challenge")
	}

	// Check for content-based indicators
	protectionKeywords := []string{"cloudflare", "captcha", "Attention Required", "challenge", "verify you are human", "security check", "DDoS protection", "Access denied"}
	for _, keyword := range protectionKeywords {
		if helpers.ContainsAny(bodyStr, []string{keyword}) {
			detectedProtections = append(detectedProtections, "Content contains: "+keyword)
		}
	}

	if len(detectedProtections) > 0 {
		detectionMsg := "Bot protection detected:\n"
		for i, detection := range detectedProtections {
			detectionMsg += fmt.Sprintf("  %d. %s\n", i+1, detection)
		}

		panic(httpError{
			url:     url,
			code:    300,
			message: detectionMsg,
			error:   resp,
		})
	}

	return resp
}
