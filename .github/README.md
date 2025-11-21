# Engine-AntiGinx Documentation

## Project Structure

```
Engine-AntiGinx/
├── App/
│   ├── Errors/
│   │   └── ErrorTypes.go         # Error structures
│   ├── Helpers/
│   │   └── StringHandling.go     # String utility functions
│   ├── HTTP/
│   │   └── HttpClient.go         # HTTP wrapper implementation
│   ├── Parameter-Parser/
│   │   └── parameter_parser.go   # Parameter parser
│   ├── Registry/
│   │   └── TestRegistry.go       # Register for available tests
│   ├── Reporter/
│   │   └── backend_reporter.go   # Tests reporter
│   ├── Runner/
│   │   └── JobRunner.go          # Tests orchestrator
│   └── Tests/
│       ├── Types.go              # Test framework types and structures
│       └── HTTPSTest.go          # HTTPS protocol security test
│
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

## Tests Framework

The Tests framework provides a structured approach for implementing security and functionality tests on HTTP responses. It includes base types, interfaces, and specific test implementations.

### Types.go - Core Framework

The `Types.go` file contains the fundamental structures and types that power the testing framework.

#### ThreatLevel Enumeration

```go
type ThreatLevel int

const (
    None ThreatLevel = iota  // 0 - No security issues detected
    Info                     // 1 - Informational findings
    Low                      // 2 - Low risk security issues
    Medium                   // 3 - Medium risk security issues
    High                     // 4 - High risk security issues
    Critical                 // 5 - Critical security vulnerabilities
)
```

#### TestResult Structure

```go
type TestResult struct {
    Name        string                // Test name
    Certainty   int                   // Confidence percentage (0-100)
    ThreatLevel ThreatLevel           // Security threat level
    Metadata    any                   // Additional test-specific data
    Description string                // Human-readable result description
}
```

#### ResponseTest Structure

```go
type ResponseTest struct {
    Id          string                                          // Unique test identifier
    Name        string                                          // Human-readable test name
    Description string                                          // Detailed test description
    RunTest     func(params ResponseTestParams) TestResult      // Test execution function
}
```

**Methods:**

- `GetId() string` - Returns the test's unique identifier
- `GetName() string` - Returns the test's display name
- `GetDescription() string` - Returns the test's detailed description
- `Run(params ResponseTestParams) TestResult` - Executes the test logic

#### ResponseTestParams

```go
type ResponseTestParams struct {
    Response *http.Response  // HTTP response to be analyzed
}
```

Contains the HTTP response object that tests will analyze for security issues, headers, content, and other properties.

### HTTPSTest.go - Protocol Security Test

The `HTTPSTest.go` file implements a specific test that verifies whether HTTP communication uses the secure HTTPS protocol.

#### Test Implementation

```go
func NewHTTPSTest() *ResponseTest {
    return &ResponseTest{
        Id:          "https-protocol-check",
        Name:        "HTTPS Protocol Verification",
        Description: "Verifies if the website communication is secured with HTTPS protocol",
        RunTest: func(params ResponseTestParams) TestResult {
            // Implementation checks params.Response.Request.URL.Scheme
        },
    }
}
```

#### Test Logic

The HTTPS test performs the following analysis:

1. **Protocol Detection**: Examines `response.Request.URL.Scheme` to determine if HTTPS was used
2. **Security Assessment**: Evaluates the security implications of the detected protocol
3. **Result Generation**: Returns detailed results with appropriate threat levels

#### Test Results

**✅ HTTPS Detected (Secure Connection)**

```json
{
  "name": "HTTPS Protocol Verification",
  "certainty": 100,
  "threatLevel": 0,
  "metadata": {
    "protocol": "https",
    "secure": true,
    "url": "https://example.com",
    "status_code": 200
  },
  "description": "Connection is secured with HTTPS protocol - data transmission is encrypted"
}
```

**⚠️ HTTP Detected (Insecure Connection)**

```json
{
  "name": "HTTPS Protocol Verification",
  "certainty": 100,
  "threatLevel": 4,
  "metadata": {
    "protocol": "http",
    "secure": false,
    "url": "http://example.com",
    "status_code": 200,
    "vulnerability": "Unencrypted data transmission"
  },
  "description": "Connection uses insecure HTTP protocol - data is transmitted in plaintext and vulnerable to interception"
}
```

### Usage Example

```go
import (
    HttpClient "Engine-AntiGinx/App/HTTP"
    Tests "Engine-AntiGinx/App/Tests"
)

func main() {
    // Make HTTP request
    httpClient := HttpClient.CreateHttpWrapper()
    response := httpClient.Get("https://example.com")

    // Create and run HTTPS test
    httpsTest := Tests.NewHTTPSTest()
    params := Tests.ResponseTestParams{Response: response}
    result := httpsTest.Run(params)

    // Process results
    fmt.Printf("Test: %s (ID: %s)\n", httpsTest.GetName(), httpsTest.GetId())
    fmt.Printf("Threat Level: %v\n", result.ThreatLevel)
    fmt.Printf("Description: %s\n", result.Description)
}
```

### Framework Benefits

1. **🔧 Extensible Design**: Easy to add new tests by implementing the `ResponseTest` structure
2. **📊 Structured Results**: Consistent `TestResult` format with threat levels and metadata
3. **🛡️ Security Focus**: Built-in threat level classification for security assessment
4. **📱 JSON Ready**: Struct tags ensure proper JSON serialization for APIs
5. **🎯 Modular Architecture**: Each test is self-contained and independently executable

### Creating Custom Tests

To implement a new test:

1. **Create Test Function**:

```go
func NewMyCustomTest() *ResponseTest {
    return &ResponseTest{
        Id:          "my-custom-test",
        Name:        "My Custom Test",
        Description: "Description of what this test does",
        RunTest:     func(params ResponseTestParams) TestResult {
            // Your test logic here
            return TestResult{...}
        },
    }
}
```

2. **Implement Test Logic**: Analyze the `params.Response` object
3. **Return Results**: Provide appropriate `TestResult` with threat level and metadata

This framework provides a solid foundation for building comprehensive security testing capabilities for web applications and APIs.

---

### Test Registry

The `Registry` package acts as the central, thread-safe storage for all available ResponseTests. It handles the registration and retrieval of test definitions.

#### Structure and Storage

The registry uses an internal map to store test pointers, indexed by their string IDs.

```go
var tests = make(map[string]*Tests.ResponseTest)
```

#### Registration

Tests are registered automatically using the `init()` function and the internal `registerTest` helper.

```go
func init() {
    registerTest(Tests.NewHTTPSTest())
}
```

**Panic Conditions:**
- **Code 100**: Triggers if a test with the same ID is registered more than once. This ensures unique identifiers for all tests in the system.

#### Retrieval

```go
func GetTest(testId string) (*Tests.ResponseTest, bool)
```

**Purpose:** Retrieves a specific test implementation by its ID.

**Parameters:**
- `testId`: The string identifier of the test (e.g., "https-protocol-check").

**Returns:**
- `*Tests.ResponseTest`: Pointer to the test object.
- `bool`: `true` if found, `false` otherwise.

---

### Backend Reporter

The `Reporter` package handles the consumption of `TestResult` objects and forwards them to an external backend service. It is designed using the **Producer-Consumer** pattern with Go channels.

#### Structure

```go
type backendReporter struct {
    resultChannel <-chan Tests.TestResult // Receive-only channel
    backendURL    string
}
```

#### Initialization

```go
func InitializeBackendReporter(channel chan Tests.TestResult, backendURL string) *backendReporter
```

Creates a reporter instance listening on the provided channel.

#### Listening (Async)

```go
func (b *backendReporter) StartListening() <-chan bool
```

**Behavior:**
- Spawns a **goroutine** to process results asynchronously.
- Iterates over `resultChannel` until the channel is closed by the sender.
- Returns a `done` channel (bool) that signals when all processing is complete.

**Usage Flow:**
1. Initialize Reporter with a channel.
2. Call `StartListening()`.
3. Produce test results into the channel.
4. Close the channel.
5. Wait on the `done` channel for graceful shutdown.

---

### Job Runner

The `jobRunner` is the central orchestrator of the application. It connects the Parameter Parser, HTTP Wrapper, Test Registry, and Reporter to execute a scanning job.

#### Creation

```go
func CreateJobRunner() *jobRunner
```

#### Orchestrate Method

```go
func (j *jobRunner) Orchestrate(params []*parameterparser.CommandParameter)
```

**Workflow:**
1. **Parsing:** Scans the `CommandParameter` list for the `--tests` flag to determine which tests to run.
2. **Validation:** Panics if no tests are found or if a requested test ID does not exist in the `Registry`.
3. **Execution:**
    - Loads the target website content (once) via `loadWebsiteContent`.
    - Initializes the `backendReporter`.
    - Uses a `sync.WaitGroup` to spawn concurrent goroutines for each requested test.
4. **Synchronization:** Waits for all tests to finish (`wg.Wait`), closes the results channel, and waits for the reporter to finish (`<-doneChannel`).

**Error Codes:**

| Code | Description |
| --- | --- |
| **100** | **Runner Error:** No tests were found to execute (missing `--tests` arg). |
| **201** | **Parsing Error:** A test ID provided in arguments does not exist in the Registry. |

#### Internal Concurrency Model

The runner uses a fan-out pattern where one HTTP response is shared among multiple test workers:

```go
go performTest(t, &wg, channel, result)
```

- `performTest`: Executes the specific `ResponseTest` logic and sends the `TestResult` into the reporter's channel.
- `defer wg.Done()`: Ensures the WaitGroup is decremented even if a test fails.

---
