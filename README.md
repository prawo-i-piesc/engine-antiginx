# Engine-AntiGinx Documentation

## Project Structure

```
Engine-AntiGinx/
├── Helpers/
│   └── StringHandling.go     # String utility functions
├── HTTP/
│  └── Client.go             # HTTP wrapper implementation
├── Parameter-Parser/
│  └── parameter-parser.go  # Parameter parser
├── Shared/
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
- Iterative function which checks if there is more than one occurrences of the same argument 

---

## Error Handling

The package uses a panic-based system with structured `parsingError`. External code should use `defer` + `recover` to catch and handle errors.


### Error Codes Used in the Package

| Code    | Meaning | Description |
|---------| ------- | ----------- |
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

