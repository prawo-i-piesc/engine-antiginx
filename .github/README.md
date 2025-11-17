# Engine-AntiGinx Documentation

## Project Structure

```
Engine-AntiGinx/
├── App/
│   ├── Helpers/
│   │   └── StringHandling.go     # String utility functions
│   ├── HTTP/
│   │   └── HttpClient.go         # HTTP wrapper implementation
│   └── Parameter-Parser/
│       └── parameter_parser.go   # Parameter parser
├── main.go                       # Main application entry point
├── go.mod                        # Go module definition
└── .github/                      # GitHub configuration and documentation
```

### httpWrapper

The `httpWrapper` is the main component that wraps Go's standard `http.Client` with additional bot protection detection capabilities and configurable headers.

#### Structure

```go
type httpWrapper struct {
    client *http.Client
    config httpWrapperConfig
}

type httpWrapperConfig struct {
    headers map[string]string
}
```

#### Creation

```go
func CreateHttpWrapper(opts ...WrapperOption) *httpWrapper
```

Creates a new instance of httpWrapper with configurable options. Supports default headers and custom configurations.

**Examples:**

```go
// Create wrapper with default headers
wrapper := HttpClient.CreateHttpWrapper()

// Create wrapper with custom headers
wrapper := HttpClient.CreateHttpWrapper(HttpClient.WithHeaders(map[string]string{
    "User-Agent": "CustomBot/2.0",
    "Authorization": "Bearer token123",
}))
```

#### Configuration Options

```go
type WrapperOption func(*httpWrapperConfig)

// WithHeaders adds or overrides headers in the wrapper configuration
func WithHeaders(h map[string]string) WrapperOption
```

**Default Headers:**

```go
func defaultHeaders() map[string]string {
    return map[string]string{
        "User-Agent": "AntiGinx/1.0",
    }
}
```

### HTTP Methods

#### Get Method

```go
func (hw *httpWrapper) Get(url string, opts ...WrapperOption) *http.Response
```

Performs an HTTP GET request with built-in bot protection detection and error handling. This is now a **method** on the httpWrapper struct.

**Parameters:**

- `url`: Target URL string
- `opts`: Optional configuration overrides for this specific request

**Returns:**

- `*http.Response`: HTTP response object (only if successful)

**Examples:**

```go
// Import the package
import HttpClient "Engine-AntiGinx/App/HTTP"

// Create wrapper with default headers
wrapper := HttpClient.CreateHttpWrapper()

// Basic GET request
response := wrapper.Get("https://example.com")

// GET request with per-call header overrides
response := wrapper.Get("https://example.com", HttpClient.WithHeaders(map[string]string{
    "User-Agent": "SpecialBot/1.0",
    "Accept": "application/json",
}))

// Complete usage example with error handling
func main() {
    defer func() {
        if r := recover(); r != nil {
            // Handle error without referencing unexported type
            fmt.Printf("HTTP error: %v\n", r)
        }
    }()

    wrapper := HttpClient.CreateHttpWrapper()
    response := wrapper.Get("https://example.com")
    fmt.Printf("Success! Status: %s\n", response.Status)
}
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
| **100** | Request Creation Error | Failed to create HTTP request |
| **101** | Network Error | Network-related failures including DNS lookup failures, connection timeouts, network unreachable, or no response object |
| **102** | HTTP Status Error | Non-200 HTTP status codes returned by the server |
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

### Parameter_Parser

`Parameter_Parser` is a package for parsing CLI command input parameters. It processes a list of tokens (program arguments) based on statically defined parameter definitions in code. Parsing is validated for required arguments, allowed values (whitelist), and default values. The package uses a panic-based error handling system with structured error information.

---

#### Structures

```go
type parameterParser struct{}

type commandParameter struct {
	Name      string
	Arguments []string
}

type parameter struct {
	Arguments   []string
	DefaultVal  string
	ArgRequired bool
	ArgCount int
}

type parsingError struct {
	Code    int
	Message string
}
```

- `parameterParser` — the parser object.
- `commandParameter` — a resulting record with the parameter name and its arguments.
- `parameter` — structure describing a single parameter from static Map. Arg count can be 1 (takes only one argument) or -1 (takes multiple arguments)
- `parsingError` — structured error used in panic.

---

#### Parser Creation

```go
func CreateCommandParser() *parameterParser {
	return &parameterParser{}
}
```

- Factory function to create a new parser instance.
- Example:

```go
parser := CreateCommandParser()
```

---

#### Parse Method

```go
func (p *parameterParser) Parse(userParameters []string) []commandParameter
```

- Method of the `parameterParser` struct.
- Validates input parameters:
  - Must contain at least 2 tokens.
  - Second token must be `"test"`.
- Transforms user input via `transformIntoTable`.
- Returns `[]commandParameter`.

**Example usage:**

```go
parser := CreateCommandParser()
parsed := parser.Parse(os.Args)
fmt.Println(parsed)
```

---

#### Main Function Example

```go
func main() {
	parser := CreateCommandParser()
	fmt.Println(parser.Parse(os.Args))
}
```

---

##### transformIntoTable

```go
func transformIntoTable(params map[string]parameter, userParameters []string) []commandParameter
```

- Core parsing algorithm.
- Inputs:
  - `params` — map of defined parameters.
  - `userParameters` — tokens provided by the user.
- Logic (summary):
  - Iterates tokens starting from index `2`.
  - If a token is a known parameter (`params[token]`):
    - If the parameter requires arguments (`ArgRequired == true`) — turns on argument collection mode (`argMode = true`) and collects subsequent tokens as arguments (validates them if whitelist exists).
    - If the parameter does **not** require arguments:
      - If the next token is a parameter — use `DefaultVal`.
      - If the next token is not a parameter — treat it as the argument (and skip it in iteration).
  - If a token is not a known parameter:
    - If `argMode` is off — panic (unexpected argument).
    - If `argMode` is on — treat token as argument for the current parameter; if `Arguments` whitelist exists, validate via `findElement`.
  - After finishing the loop, if `argMode` is still on, append the collected arguments as the last parameter.
- Returns `[]commandParameter`.

---

##### findElement

```go
func findElement(userParam string, params []string) bool
```

- Simple linear search — checks if `userParam` exists in `params`.
- Used for whitelist validation.

---

#### checkOccurences

```go
func checkOccurences(args []string)
```

- Iterative function which checks if there is more than one occurrence of the same argument

---

## Error Handling

The package uses a panic-based system with structured `parsingError`. External code should use `defer` + `recover` to catch and handle errors.

### Error Codes Used in the Package

| Code | Meaning | Description |
| --- | --- | --- |
| **100** | General parsing error | e.g., not enough parameters. |
| **201** | Missing `"test"` keyword / invalid structure | When `userParameters[1] != "test"`. |
| **303** | Missing required arguments | Parameter requires arguments, but none provided. |
| **304** | Unknown parameter / invalid argument | Token is not a parameter and no active `argMode`, or argument not in whitelist. |
| **305** | Invalid user input | Same argument appears more than once in provided input |
| **306** | Invalid user input | Too many arguments passed to the parameter |

## Input/Output Examples

1. Input (assuming `os.Args`):

```
["scanner", "test", "--target", "example.com", "--httpMethods", "GET", "OPTIONS", "--tests", "https", "hsts"]
```

Result of `Parse(...)`:

```go
[]commandParameter{
  {Name: "--target", Arguments: []string{"example.com"}},
  {Name: "--httpMethods", Arguments: []string{"GET","OPTIONS"}},
  {Name: "--tests", Arguments: []string{"https", "hsts"}},
}
```

2. Input missing argument for required parameter:

```
["scanner", "test", "--target"]
```

- Triggers `panic(parsingError{Code:303, ...})` - too few arguments for `--target`.

3. Invalid argument (not in whitelist):

```
["app", "test", "--httpMethods", "BADMETHOD"]
```

— triggers `panic(parsingError{Code:304, ...})` - invalid argument passed to the parameter.

---
