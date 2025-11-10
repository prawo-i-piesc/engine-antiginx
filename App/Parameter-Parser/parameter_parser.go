package Parameter_Parser

import (
	"encoding/json"
	"os"
)

type parameterParser struct{}
type commandParameter struct {
	Name      string
	Arguments []string
}
type parameter struct {
	Arguments   []string `json:"arguments"`
	DefaultVal  string   `json:"defaultVal"`
	ArgRequired bool     `json:"argRequired"`
}
type parsingError struct {
	Code    int
	Message string
	Error   any
}

func CreateCommandParser() *parameterParser {
	return &parameterParser{}
}

func (p *parameterParser) Parse(userParameters []string) []commandParameter {
	paramLen := len(userParameters)
	if paramLen < 2 {
		panic(parsingError{
			Code: 100,
			Message: `Parsing error occurred. This could be due to:
				- insufficient number of parameters`,
			Error: nil,
		})
	}
	//Checking if test keyword is present or is at its position
	//Raise error if not
	if userParameters[1] != "test" {
		panic(parsingError{
			Code: 201,
			Message: `Parsing error occurred. This could be due to:
				- test keyword is not present
				- structure of the command is invalid`,
			Error: nil,
		})
	}
	params := parseJsonFile()

	return transformIntoTable(params, userParameters)
}

/*
Function which transforms and validates user data into commands table

		variables:
			parsedParams: table with parsed and validated parameters and its arguments
			currentParam: variable that stores current param if argMode is on
			args: buffer for the arguments
		modes:
			argMode - variable which helps to track if current userParam is parameter
				or one of arguments to the parameter
		Explanation:
			For each token:

	  - Check if the token is a known parameter (params[token]):
	    -> If YES:

	  - If argMode is ON (collecting arguments for a previous parameter):

	  - Turn argMode OFF

	  - If args is empty -> panic (missing required arguments)

	  - Copy args into a new slice (argCopy)

	  - Append {Name: currentParam, Arguments: argCopy} to parsedParams

	  - Clear args for reuse

	  - Handle the current parameter:

	  - If the parameter REQUIRES arguments (ArgRequired == true):

	  - If this is the last token -> panic (missing required argument)

	  - Turn argMode ON and set currentParam = token (start collecting arguments)

	  - If the parameter does NOT require arguments (ArgRequired == false):

	  - If there is a next token:
	    · If next token is another parameter:

	  - Append {Name: token, Arguments: []} (no custom value)
	    · Else (next token is not a parameter):

	  - Treat next token as a user-provided argument

	  - Append {Name: token, Arguments: [next]}

	  - Increment i (consume the argument)

	  - If no next token exists:

	  - Append {Name: token, Arguments: [defaultVal]} (use default)

	    -> If NO (token is not a parameter name):

	  - If argMode is OFF -> panic (unexpected argument with no active parameter)

	  - If argMode is ON:

	  - If the parameter has a whitelist of allowed arguments,
	    check using findElement; if invalid -> panic

	  - Append token to args (it is an argument)

After finishing the loop:
  - If argMode is still ON (unfinished argument collection):
    -> If args is empty -> panic
    -> Copy args and append the final {Name: currentParam, Arguments: argCopy}

Return parsedParams.
*/
func transformIntoTable(params map[string]parameter, userParameters []string) []commandParameter {
	userParametersLen := len(userParameters)
	var parsedParams []commandParameter
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
					panic(parsingError{
						Code: 403,
						Message: `Parsing error occurred. This could be due to:
							- too few arguments passed to arg required param`,
						Error: nil,
					})
				}
				argCopy := append([]string(nil), args...)
				parsedParams = append(parsedParams, commandParameter{
					Name:      currentParam,
					Arguments: argCopy,
				})
				// clear args for reuse
				args = args[:0]
			}
			if v.ArgRequired {
				if userParametersLen == i+1 {
					panic(parsingError{
						Code: 403,
						Message: `Parsing error occurred. This could be due to:	
							- too few arguments passed to arg required param`,
						Error: nil,
					})
				}
				argMode = true
				currentParam = token
			} else {
				if userParametersLen > i+1 {
					next := userParameters[i+1]
					_, ok := params[next]
					if ok {
						parsedParams = append(parsedParams, commandParameter{
							Name:      token,
							Arguments: []string{v.DefaultVal},
						})
						continue
					} else {
						parsedParams = append(parsedParams, commandParameter{
							Name:      token,
							Arguments: []string{next},
						})
						i++
						continue
					}
				} else {
					parsedParams = append(parsedParams, commandParameter{
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
						panic(parsingError{
							Code: 404,
							Message: `Parsing error occurred. This could be due to:
								- invalid argument passed to the parameter`,
							Error: nil,
						})
					}
					args = append(args, token)
				} else {
					args = append(args, token)
				}

			} else {
				panic(parsingError{
					Code: 404,
					Message: `Parsing error occurred. This could be due to:
						- invalid argument passed to the parameter`,
					Error: nil,
				})
			}
		}
	}
	if argMode {
		argMode = false
		argCopy := append([]string(nil), args...)
		parsedParams = append(parsedParams, commandParameter{
			Name:      currentParam,
			Arguments: argCopy,
		})
		args = args[:0]
	}

	return parsedParams
}
func findElement(userParam string, params []string) bool {
	for i := 0; i < len(params); i++ {
		if params[i] == userParam {
			return true
		}
	}
	return false
}
func parseJsonFile() map[string]parameter {
	bs, err := os.ReadFile("App/Shared/commands.json")
	//Checking if file with built-in commands is parsed correctly
	if err != nil {
		panic(parsingError{
			Code: 302,
			Message: `Parsing error occurred. This could be due to:
				- internal error`,
			Error: err,
		})
	}

	var params map[string]parameter
	if err := json.Unmarshal(bs, &params); err != nil {
		panic(parsingError{
			Code: 302,
			Message: `Parsing error occurred. This could be due to:
				- internal error`,
			Error: err,
		})
	}
	return params
}
