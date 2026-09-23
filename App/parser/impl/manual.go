// Package impl provides parameter parser implementations.
package impl

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/parser/config"
	"Engine-AntiGinx/App/parser/config/types"
)

// parameterParser validates manual command-line arguments.
type parameterParser struct{}

// CreateCommandParser creates a manual argument parser.
func CreateCommandParser() *parameterParser {
	return &parameterParser{}
}

// Parse validates manual command-line arguments.
func (p *parameterParser) Parse(userParameters []string) []*types.CommandParameter {
	length := len(userParameters)
	if length < 3 {
		panic(error.Error{
			Code: 100,
			Message: `Parsing error occurred. This could be due to:
				- insufficient number of parameters`,
			Source:      "parser",
			IsRetryable: false,
		})
	}
	return transformIntoTable(config.Params, userParameters)
}

// transformIntoTable collects and validates arguments for each parameter.
func transformIntoTable(params map[string]types.Parameter, userParameters []string) []*types.CommandParameter {
	userParametersLen := len(userParameters)
	parsedParams := []*types.CommandParameter{}
	var currentParam string
	var args []string
	argMode := false
	for i := 2; i < userParametersLen; i++ {
		token := userParameters[i]
		v, ok := params[token]
		if ok {
			if argMode {
				if len(args) == 0 {
					panic(error.Error{
						Code: 303,
						Message: `Parsing error occurred. This could be due to:
							- too few arguments passed to arg required param`,
						Source:      "parser",
						IsRetryable: false,
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
							Source:      "parser",
							IsRetryable: false,
						})
					}
				}
				argCopy := append([]string(nil), args...)
				parsedParams = append(parsedParams, &types.CommandParameter{
					Name:      currentParam,
					Arguments: argCopy,
				})
				// clear args for reuse
				args = args[:0]
			}
			argMode = v.ArgRequired
			if v.ArgRequired {
				if userParametersLen == i+1 {
					panic(error.Error{
						Code: 303,
						Message: `Parsing error occurred. This could be due to:	
							- too few arguments passed to arg required param`,
						Source:      "parser",
						IsRetryable: false,
					})
				}
				currentParam = token
			} else {
				consumedNext := false
				if userParametersLen > i+1 {
					next := userParameters[i+1]
					_, nextIsParam := params[next]

					if !nextIsParam {
						if v.ArgCount == 0 {
							panic(error.Error{
								Code: 306,
								Message: `Parsing error occurred. This could be due to:
								- unnecessary argument passed to the parameter`,
								Source:      "parser",
								IsRetryable: false,
							})
						}
						parsedParams = append(parsedParams, &types.CommandParameter{
							Name:      token,
							Arguments: []string{next},
						})
						i++
						consumedNext = true
					}
				}
				if !consumedNext {
					defaultArgs := []string{}
					if v.ArgCount != 0 {
						defaultArgs = []string{v.DefaultVal}
					}
					parsedParams = append(parsedParams, &types.CommandParameter{
						Name:      token,
						Arguments: defaultArgs,
					})
				}
			}
		} else {
			if argMode {
				v := params[currentParam]
				if len(v.Arguments) > 0 {
					if !findElement(token, v.Arguments) {
						panic(error.Error{
							Code: 304,
							Message: `Parsing error occurred. This could be due to:
								- invalid argument passed to the parameter`,
							Source:      "parser",
							IsRetryable: false,
						})
					}
					args = append(args, token)
				} else {
					if v.ArgCount == 1 && len(args) == v.ArgCount {
						panic(error.Error{
							Code: 306,
							Message: `Parsing error occurred. This could be due to:
								- unnecessary argument passed to the parameter`,
							Source:      "parser",
							IsRetryable: false,
						})
					}
					args = append(args, token)
				}
			} else {
				panic(error.Error{
					Code: 304,
					Message: `Parsing error occurred. This could be due to:
						- invalid argument passed to the parameter`,
					Source:      "parser",
					IsRetryable: false,
				})
			}
		}
	}
	if argMode {
		checkOccurrences(args)
		argCopy := append([]string(nil), args...)
		parsedParams = append(parsedParams, &types.CommandParameter{
			Name:      currentParam,
			Arguments: argCopy,
		})
	}

	return parsedParams
}

// findElement checks whether an argument is allowed.
func findElement(userParam string, params []string) bool {
	for i := 0; i < len(params); i++ {
		if params[i] == userParam {
			return true
		}
	}
	return false
}

// checkOccurrences rejects repeated argument values.
func checkOccurrences(args []string) {
	seen := make(map[string]bool)
	for _, curr := range args {
		if seen[curr] {
			panic(error.Error{
				Code: 305,
				Message: `Parsing error occurred. This could be due to:
					- one of the arguments occurred more than once`,
				Source:      "parser",
				IsRetryable: false,
			})
		}
		seen[curr] = true
	}
}
