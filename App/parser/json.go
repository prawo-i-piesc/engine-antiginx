package parser

import (
	"Engine-AntiGinx/App/Errors"
	"encoding/json"
	"fmt"
	"os"
)

// TestJson represents the root structure of the configuration file.
// It maps directly to the JSON input containing the target URL and a list of parameters.
type TestJson struct {
	Target     string              `json:"Target"`
	Parameters []*CommandParameter `json:"Parameters"`
}

// JsonParser is responsible for reading, deserializing, and validating
// configuration logic from a JSON file.
type JsonParser struct{}

// CreateJsonParser initializes and returns a new instance of JsonParser.
func CreateJsonParser() *JsonParser {
	return &JsonParser{}
}

// Parse orchestrates the parsing process. It expects userParameters to contain
// the filename at index 2. It reads the file, validates parameters against
// defined rules, and returns a consolidated list of CommandParameter objects.
//
// It prepends the target as a "--target" parameter to the final list.
// This method panics if validation fails or the file cannot be read.
func (j *JsonParser) Parse(userParameters []string) []*CommandParameter {
	length := len(userParameters)
	if length < 3 {
		message := `Json parser error occurred. This could be due to:
				- insufficient number of parameters`
		j.throwPanic(100, message)
	}
	fileName := userParameters[2]

	testJson := j.deserializeWithErrorHandling(fileName)

	if testJson.Target == "" || testJson.Parameters == nil || len(testJson.Parameters) == 0 {
		message := `Json parser error occurred. This could be due to:
				- empty target
				- not given or empty parameters`
		j.throwPanic(101, message)
	}

	target := testJson.Target
	params := testJson.Parameters

	j.checkParameters(params)
	finalList := append([]*CommandParameter{&CommandParameter{
		Name:      "--target",
		Arguments: []string{target},
	}}, params...)
	return finalList
}

// checkParameters iterates through the provided parameters and validates them
// against the global Params whitelist.
//
// It performs several checks:
//   - Checks for nil references.
//   - Verifies if the parameter name exists in the whitelist.
//   - Validates argument counts (min/max constraints).
//   - Applies default values for optional parameters if arguments are missing.
//   - Delegates specific argument validation to checkArgs.
func (j *JsonParser) checkParameters(params []*CommandParameter) {
	for _, val := range params {
		if val == nil {
			message := `Json parser error occurred. This could be due to:
				- nil parameter`
			j.throwPanic(200, message)
		}
		arguments := val.Arguments
		if arguments == nil {
			val.Arguments = []string{}
		}
		name := val.Name
		length := len(arguments)

		token, ok := Params[name]
		if !ok {
			message := `Json parser error occurred. This could be due to:
				- invalid parameter`
			j.throwPanic(201, message)
		}

		if token.ArgRequired && length < 1 {
			message := `Json parser error occurred. This could be due to:
				- too few arguments passed to the parameter`
			j.throwPanic(202, message)
		}

		if token.ArgCount == 1 && length > 1 {
			message := `Json parser error occurred. This could be due to:
				- too many arguments passed to the parameter`
			j.throwPanic(203, message)
		}

		if length < 1 && !token.ArgRequired {
			val.Arguments = append(val.Arguments, token.DefaultVal)
		}

		if len(token.Arguments) > 0 {
			j.checkArgs(token.Arguments, arguments)
		}
	}
}

// checkArgs verifies that the given arguments are allowed for a specific parameter.
// It checks if the arguments exist in the 'args' whitelist and detects duplicates.
//
// It panics if:
//   - An argument is not in the whitelist (Error 204).
//   - An argument appears more than once (Error 205).
func (j *JsonParser) checkArgs(args []string, givenArgs []string) {
	validityMap := make(map[string]bool, len(args))
	for _, val := range args {
		validityMap[val] = false
	}

	for _, val := range givenArgs {
		occurrence, ok := validityMap[val]
		if !ok {
			message := `Json parser error occurred. This could be due to:
				- invalid argument passed to the parameter`
			j.throwPanic(204, message)
		}
		if occurrence {
			message := `Json parser error occurred. This could be due to:
				- one of the arguments occur more than once`
			j.throwPanic(205, message)
		}
		validityMap[val] = true
	}
}

// deserializeWithErrorHandling reads the file from the disk and unmarshalls it into a TestJson struct.
// It handles file I/O errors and JSON syntax errors by triggering a panic with a descriptive message.
func (j *JsonParser) deserializeWithErrorHandling(fileName string) *TestJson {
	// Empty file name case
	if fileName == "" {
		message := `Json parser error occurred. This could be due to:
				- empty file name`
		j.throwPanic(102, message)
	}

	file, err := os.ReadFile(fileName)
	// Opening file error case
	if err != nil {
		message := fmt.Sprintf("Json parser error occurred. This could be due to: \n"+
			"- %v", err)
		j.throwPanic(103, message)
	}

	var testJson TestJson
	err2 := json.Unmarshal(file, &testJson)
	// Deserialization error
	if err2 != nil {
		message := fmt.Sprintf("Json parser error occurred. This could be due to: \n"+
			"- %v", err2)
		j.throwPanic(104, message)
	}
	return &testJson
}

// throwPanic is a helper method to construct and panic with a standard application Error.
// This is used to interrupt the control flow when a validation or parsing error occurs.
func (j *JsonParser) throwPanic(code int, message string) {
	panic(Errors.Error{
		Code:        code,
		Message:     message,
		Source:      "json parser",
		IsRetryable: false,
	},
	)
}
