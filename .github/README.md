# Engine-AntiGinx Documentation

## Project Structure

```
Engine-AntiGinx/
├── Helpers/
│   └── StringHandling.go     # String utility functions
└── HTTP/
    └── Client.go             # HTTP wrapper implementation
```

### httpWrapper

The `httpWrapper` is the main component that wraps Go's standard `http.Client` with additional bot protection detection capabilities.

#### Structure

```go
type httpWrapper struct {
    client *http.Client
}
```

#### Creation

```go
func createHttpWrapper() *httpWrapper
```

Creates a new instance of httpWrapper with a default HTTP client.

**Example:**

```go
wrapper := createHttpWrapper()
```

### HTTP Functions

#### Get Function

```go
func Get(hw *httpWrapper, url string) *http.Response
```

Performs an HTTP GET request with built-in bot protection detection and error handling.

**Parameters:**

- `hw`: Pointer to httpWrapper instance
- `url`: Target URL string

**Returns:**

- `*http.Response`: HTTP response object (only if successful)

**Example:**

```go
wrapper := createHttpWrapper()
response := Get(wrapper, "https://example.com")
```

## Error Handling

The httpWrapper uses a panic-based error handling system with structured error information.

### httpError Structure

```go
type httpError struct {
    url     string  // The URL that caused the error
    code    int     // Internal error code
    message string  // Human-readable error description
    error   any     // Original error object
}
```

### Error Codes

| Code | Category | Description |
| --- | --- | --- |
| **100** | Network Error | Network-related failures including DNS lookup failures, connection timeouts, network unreachable, or no response object |
| **101** | HTTP Status Error | Non-200 HTTP status codes returned by the server |
| **200** | Response Body Error | Errors encountered while reading the response body |
| **300** | Bot Protection Detected | Various bot protection mechanisms detected |

#### Error Code 300 - Bot Protection Detected

**Triggers when:** Bot protection mechanisms are detected through:

**Header-based detection:**

- `Server: cloudflare`
- `CF-RAY` header present
- `CF-CHL-BCODE` header present (Cloudflare Challenge)

**Content-based detection:** The system scans response body for these keywords:

- "cloudflare"
- "captcha"
- "Attention Required"
- "challenge"
- "verify you are human"
- "security check"
- "DDoS protection"
- "Access denied"

**Example scenarios:**

- Cloudflare challenge page
- CAPTCHA verification page
- DDoS protection page
- Access denied pages

## Helper Functions

### StringHandling.ContainsAny

Located in `Helpers/StringHandling.go`

```go
func ContainsAny(s string, subs []string) bool
```

**Purpose:** Case-insensitive search for any substring within a target string.

**Parameters:**

- `s`: Target string to search in
- `subs`: Array of substrings to search for

**Returns:**

- `bool`: true if any substring is found, false otherwise
