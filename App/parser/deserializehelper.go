package parser

import (
	"Engine-AntiGinx/App/Errors"
	"encoding/json"
	"fmt"
)

// TestJson represents the root structure of the configuration file.
// It maps directly to the JSON input containing the target URL and a list of parameters.
type TestJson struct {
	Target     string              `json:"Target"`
	Parameters []*CommandParameter `json:"Parameters"`
}

func DeserializeTests(bytes []byte) (*TestJson, *Errors.Error) {
	var testJson TestJson
	err := json.Unmarshal(bytes, &testJson)
	if err != nil {
		return nil, &Errors.Error{
			Code: 100,
			Message: fmt.Sprintf("Json parser error occurred. This could be due to: \n"+
				"- %v", err),
			Source:      "Deserialize Helper",
			IsRetryable: false,
		}
	}
	return &testJson, nil
}

// CheckParameters iterates through the provided parameters and validates them
// against the global Params whitelist.
//
// It performs several checks:
//   - Checks for nil references.
//   - Verifies if the parameter name exists in the whitelist.
//   - Validates argument counts (min/max constraints).
//   - Applies default values for optional parameters if arguments are missing.
//   - Delegates specific argument validation to checkArgs.
func CheckParameters(givenParams []*CommandParameter) *Errors.Error {
	usedParams := make(map[string]bool, len(givenParams))
	for _, val := range givenParams {
		if val == nil {
			return &Errors.Error{
				Code: 101,
				Message: `Json parser error occurred. This could be due to:
				- nil parameter`,
				Source:      "Deserialize Helper",
				IsRetryable: false,
			}
		}
		arguments := val.Arguments
		if arguments == nil {
			val.Arguments = []string{}
		}
		name := val.Name
		length := len(arguments)
		token, ok := Params[name]
		if !ok {
			return &Errors.Error{
				Code: 102,
				Message: `Json parser error occurred. This could be due to:
				- invalid parameter`,
				Source:      "Deserialize Helper",
				IsRetryable: false,
			}
		}
		if usedParams[name] {
			return &Errors.Error{
				Code: 103,
				Message: `Json parser error occurred. This could be due to:
				- one of the givenParams occur more than once`,
				Source:      "Deserialize Helper",
				IsRetryable: false,
			}
		}
		usedParams[name] = true
		if token.ArgRequired && length < 1 {
			return &Errors.Error{
				Code: 104,
				Message: `Json parser error occurred. This could be due to:
				- too few arguments passed to the parameter`,
				Source:      "Deserialize Helper",
				IsRetryable: false,
			}
		}

		if token.ArgCount == 1 && length > 1 {
			return &Errors.Error{
				Code: 105,
				Message: `Json parser error occurred. This could be due to:
				- too many arguments passed to the parameter`,
				Source:      "Deserialize Helper",
				IsRetryable: false,
			}
		}

		if length < 1 && !token.ArgRequired {
			val.Arguments = append(val.Arguments, token.DefaultVal)
		}

		if len(token.Arguments) > 0 {
			if err := checkArgs(token.Arguments, arguments); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkArgs verifies that the given arguments are allowed for a specific parameter.
// It checks if the arguments exist in the 'args' whitelist and detects duplicates.
//
// Return error if:
//   - An argument is not in the whitelist (Error 106).
//   - An argument appears more than once (Error 107).
func checkArgs(args []string, givenArgs []string) *Errors.Error {
	validityMap := make(map[string]bool, len(args))
	for _, val := range args {
		validityMap[val] = false
	}

	for _, val := range givenArgs {
		occurrence, ok := validityMap[val]
		if !ok {
			return &Errors.Error{
				Code: 106,
				Message: `Json parser error occurred. This could be due to:
				- invalid argument passed to the parameter`,
				Source:      "Deserialize Helper",
				IsRetryable: false,
			}
		}
		if occurrence {
			return &Errors.Error{
				Code: 107,
				Message: `Json parser error occurred. This could be due to:
				- one of the arguments occur more than once`,
				Source:      "Deserialize Helper",
				IsRetryable: false,
			}
		}
		validityMap[val] = true
	}
	return nil
}
