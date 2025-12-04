// Package Parameter_Parser provides CLI argument parsing functionality for the Engine-AntiGinx scanner.
// It processes command-line tokens based on statically defined parameter definitions, validates required
// arguments, enforces whitelists, and provides structured error reporting through panic-based error handling.
//
// The parser supports various parameter types including:
//   - Single-value parameters (--target, --userAgent)
//   - Multi-value parameters (--tests, --httpMethods)
//   - Optional parameters with defaults (--userAgent, --referer)
//   - Required parameters (--target, --tests, --httpMethods)
//   - Whitelist validation for specific parameters
//
// Error codes:
//   - 100: Insufficient parameters
//   - 201: Missing "test" keyword or invalid command structure
//   - 303: Missing required arguments
//   - 304: Invalid argument or unexpected parameter
//   - 305: Duplicate argument detected
//   - 306: Too many arguments for single-value parameter
package Parameter_Parser

import (
	error "Engine-AntiGinx/App/Errors"
)

// params is the static registry of all supported command-line parameters with their configurations.
// Each parameter defines:
//   - Arguments: Whitelist of allowed values (empty means any value accepted)
//   - DefaultVal: Default value when parameter is provided without arguments
//   - ArgRequired: Whether arguments are mandatory
//   - ArgCount: Number of arguments (1 for single, -1 for multiple)
var params = map[string]parameter{
	"--target": {
		Arguments:   []string{},
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    1,
	},
	"--taskId": {
		Arguments:   []string{},
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    1,
	},
	"--userAgent": {
		Arguments:   []string{},
		DefaultVal:  "Scanner/1.0",
		ArgRequired: false,
		ArgCount:    1,
	},/*
	"--referer": {
		Arguments:   []string{},
		DefaultVal:  "",
		ArgRequired: false,
		ArgCount:    1,
	},*/
	"--tests": {
		Arguments: []string{"https", "hsts", "serv-h-a", "csp", "xFrame",
			/*"refererPol", "xxss", "featurePol", "listing", "openRedirect", "fCookies", "fHttpOnly"*/},
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    -1,
	},/*
	"--httpMethods": {
		Arguments: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE",
			"CONNECT", "HEAD"},
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    -1,
	},
	"--files": {
		Arguments:   []string{},
		DefaultVal:  "",
		ArgRequired: true,
		ArgCount:    -1,
	},*/
	"--antiBotDetection": {
		Arguments:   []string{},
		DefaultVal:  "", // DefaultVal is not used for flag parameters (ArgCount: 0)
		ArgRequired: false,
		ArgCount:    0,
	},
}

// parameterParser is the main parser structure that processes command-line arguments.
// It uses the static params map for parameter definitions and validation rules.
type parameterParser struct{}

// CommandParameter represents a parsed command-line parameter with its associated arguments.
// This is the output structure returned by the parser after successful validation.
type CommandParameter struct {
	Name      string   // Parameter name (e.g., "--target", "--tests")
	Arguments []string // List of validated arguments for this parameter
}

// parameter defines the specification for a command-line parameter including validation rules.
// It is used internally by the parser to validate user input against expected parameter definitions.
type parameter struct {
	Arguments   []string // Whitelist of allowed argument values (empty = no restriction)
	DefaultVal  string   // Default value when parameter provided without arguments
	ArgRequired bool     // Whether the parameter must have arguments
	ArgCount    int      // Expected argument count: 1 for single, -1 for multiple
}

// parsingError represents a structured parsing error with categorized error codes.
// Used internally for panic-based error handling during the parsing process.
type parsingError struct {
	Code    int    // Error code for categorization
	Message string // Human-readable error description
}

// CreateCommandParser creates a new instance of the parameter parser.
// This factory function returns a parser ready to process command-line arguments.
//
// Returns:
//   - *parameterParser: A new parser instance
//
// Example:
//
//	parser := CreateCommandParser()
//	params := parser.Parse(os.Args)
func CreateCommandParser() *parameterParser {
	return &parameterParser{}
}

// Parse processes command-line arguments and returns validated parameter structures.
// It enforces the command structure: [program] test [parameters...] and validates all
// arguments against the static parameter definitions.
//
// The parser performs the following validations:
//   - Minimum argument count (at least 2 tokens required)
//   - Second token must be "test" keyword
//   - All parameters must be recognized
//   - Required arguments must be provided
//   - Arguments must pass whitelist validation if defined
//   - No duplicate arguments allowed
//   - Argument count must match parameter specification
//
// Parameters:
//   - userParameters: Command-line arguments slice (typically os.Args)
//
// Returns:
//   - []*CommandParameter: List of parsed and validated parameters with their arguments
//
// Panics:
//   - error.Error with code 100: Insufficient parameters (less than 2 tokens)
//   - error.Error with code 201: Missing "test" keyword or invalid structure
//   - Additional errors may be raised by transformIntoTable
//
// Example:
//
//	parser := CreateCommandParser()
//	params := parser.Parse([]string{"scanner", "test", "--target", "example.com", "--tests", "https"})
//	// Returns: []*CommandParameter{
//	//   {Name: "--target", Arguments: []string{"example.com"}},
//	//   {Name: "--tests", Arguments: []string{"https"}},
//	// }
func (p *parameterParser) Parse(userParameters []string) []*CommandParameter {
	paramLen := len(userParameters)
	if paramLen < 2 {
		panic(error.Error{
			Code: 100,
			Message: `Parsing error occurred. This could be due to:
				- insufficient number of parameters`,
			Source: "Parser",
		})
	}
	//Checking if test keyword is present or is at its position
	//Raise error if not
	if userParameters[1] != "test" {
		panic(error.Error{
			Code: 201,
			Message: `Parsing error occurred. This could be due to:
				- test keyword is not present
				- structure of the command is invalid`,
			Source: "Parser",
		})
	}
	return transformIntoTable(params, userParameters)
}

// transformIntoTable is the core parsing algorithm that transforms and validates user input
// into a structured list of CommandParameter objects. It implements a state machine that
// distinguishes between parameter names and their arguments.
//
// Algorithm overview:
//
// The parser uses an "argMode" flag to track whether it's currently collecting arguments:
//
// For each token (starting from index 2):
//
//  1. If token is a known parameter:
//     - If argMode is ON: finalize the previous parameter's arguments
//     - Validate argument count and check for duplicates
//     - If current parameter requires arguments: enter argMode
//     - If optional: check next token and use default or provided value
//
//  2. If token is NOT a parameter:
//     - If argMode is OFF: panic (unexpected argument)
//     - If argMode is ON: validate against whitelist and collect argument
//
// After processing all tokens, if argMode is still on, the last parameter is finalized.
//
// Variables:
//
//	parsedParams   Output list of parsed parameters.
//	currentParam   Name of the parameter currently collecting arguments.
//	args           Buffer for collecting argument values.
//	argMode        State flag indicating argument collection mode.
//
// Parameters:
//
//	params         Map of parameter definitions for validation.
//	userParameters Raw command-line tokens to parse.
//
// Returns:
//
//	[]*CommandParameter: Validated list of parameters with arguments.
//
// Panics:
//
//	error.Error with code 303: Missing required arguments or empty argument list.
//	error.Error with code 304: Invalid argument or unexpected token.
//	error.Error with code 305: Duplicate arguments detected.
//	error.Error with code 306: Too many arguments for single-value parameter.
func transformIntoTable(params map[string]parameter, userParameters []string) []*CommandParameter {
	userParametersLen := len(userParameters)
	parsedParams := []*CommandParameter{}
	var currentParam string
	var args []string
	argMode := false
	for i := 2; i < userParametersLen; i++ {
		token := userParameters[i]
		v, ok := params[token]
		if ok {
			if argMode {
				argMode = false
				if len(args) == 0 {
					panic(error.Error{
						Code: 303,
						Message: `Parsing error occurred. This could be due to:
							- too few arguments passed to arg required param`,
						Source: "Parser",
					})
				}
				checkOccurrences(args)
				b := params[currentParam].ArgCount
				if b == 1 {
					if len(args) != b {
						panic(error.Error{
							Code: 306,
							Message: `Parsing error occurred. This could be due to:
								- unnecessary argument passed to the parameter`,
							Source: "Parser",
						})
					}
				}
				argCopy := append([]string(nil), args...)
				parsedParams = append(parsedParams, &CommandParameter{
					Name:      currentParam,
					Arguments: argCopy,
				})
				// clear args for reuse
				args = args[:0]
			}
			if v.ArgRequired {
				if userParametersLen == i+1 {
					panic(error.Error{
						Code: 303,
						Message: `Parsing error occurred. This could be due to:	
							- too few arguments passed to arg required param`,
						Source: "Parser",
					})
				}
				argMode = true
				currentParam = token
			} else {
				if userParametersLen > i+1 {
					next := userParameters[i+1]
					_, ok := params[next]
					if ok {
						parsedParams = append(parsedParams, &CommandParameter{
							Name:      token,
							Arguments: []string{v.DefaultVal},
						})
						continue
					} else {
						parsedParams = append(parsedParams, &CommandParameter{
							Name:      token,
							Arguments: []string{next},
						})
						i++
						continue
					}
				} else {
					parsedParams = append(parsedParams, &CommandParameter{
						Name:      token,
						Arguments: []string{v.DefaultVal},
					})
					continue
				}
			}
		} else {
			if argMode {
				v, _ := params[currentParam]
				if len(v.Arguments) > 0 {
					if !findElement(token, v.Arguments) {
						panic(error.Error{
							Code: 304,
							Message: `Parsing error occurred. This could be due to:
								- invalid argument passed to the parameter`,
							Source: "Parser",
						})
					}
					args = append(args, token)
				} else {
					args = append(args, token)
				}
			} else {
				panic(error.Error{
					Code: 304,
					Message: `Parsing error occurred. This could be due to:
						- invalid argument passed to the parameter`,
					Source: "Parser",
				})
			}
		}
	}
	if argMode {
		argMode = false
		checkOccurrences(args)
		argCopy := append([]string(nil), args...)
		parsedParams = append(parsedParams, &CommandParameter{
			Name:      currentParam,
			Arguments: argCopy,
		})
		args = args[:0]
	}

	return parsedParams
}

// findElement performs a linear search to check if a user-provided argument exists in the
// parameter's whitelist of allowed values. This is used for validating arguments against
// parameter definitions that specify allowed values.
//
// Parameters:
//   - userParam: The argument value provided by the user
//   - params: Whitelist of allowed values for the parameter
//
// Returns:
//   - bool: true if userParam is found in the whitelist, false otherwise
//
// Example:
//
//	allowed := []string{"GET", "POST", "PUT"}
//	isValid := findElement("GET", allowed)  // returns true
//	isValid := findElement("INVALID", allowed)  // returns false
func findElement(userParam string, params []string) bool {
	for i := 0; i < len(params); i++ {
		if params[i] == userParam {
			return true
		}
	}
	return false
}

// checkOccurrences validates that no argument appears more than once in the argument list.
// This prevents duplicate values which could indicate user error or misconfiguration.
//
// The function uses a map to track seen arguments with O(n) time complexity.
//
// Parameters:
//   - args: List of arguments to check for duplicates
//
// Panics:
//   - error.Error with code 305: If any argument appears more than once
//
// Example:
//
//	args := []string{"https", "hsts", "https"}  // panics - "https" appears twice
//	args := []string{"GET", "POST", "PUT"}      // passes - all unique
func checkOccurrences(args []string) {
	seen := make(map[string]bool)
	for _, curr := range args {
		if seen[curr] {
			panic(error.Error{
				Code: 305,
				Message: `Parsing error occurred. This could be due to:
					- one of the arguments occurred more than once`,
				Source: "Parser",
			})
		}
		seen[curr] = true
	}
}
