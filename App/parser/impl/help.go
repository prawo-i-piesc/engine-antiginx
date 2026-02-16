package impl

import (
	"Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/parser/config"
	"Engine-AntiGinx/App/parser/config/types"
)

type HelpParser struct{}

// CreateHelpParser initializes and returns a new instance of the HelpParser struct.
// This function serves as the constructor for the help parser.
//
// Returns:
//   - *HelpParser: A pointer to the newly created HelpParser instance
func CreateHelpParser() *HelpParser {
	return &HelpParser{}
}

// Parse processes the raw user input arguments (slice of strings) and converts
// them into a list of CommandParameter objects.
//
// The method ignores the first two elements of `userParameters` (assuming they are
// the executable name and the "help" command itself) and iterates through the
// remaining arguments. Each argument is validated against the global configuration.
// If an argument is not recognized, the function will panic.
//
// Parameters:
//   - userParameters: The slice of input arguments provided by the user (e.g. os.Args)
//
// Returns:
//   - []*types.CommandParameter: A list of constructed command parameter objects
//
// Example:
//
//	args := []string{"scanner", "help", "--tests"}
//	parser := CreateHelpParser()
//	// Returns command parameters for "--tests"
//	commands := parser.Parse(args)
func (h *HelpParser) Parse(userParameters []string) []*types.CommandParameter {
	length := len(userParameters)
	if length < 3 {
		return []*types.CommandParameter{}
	}
	var commands []*types.CommandParameter
	for i := 2; i < length; i++ {
		val := userParameters[i]
		_, ok := config.Params[val]
		if !ok {
			panic(Errors.Error{
				Code: 100,
				Message: `Help parser error occurred. This could be due to:
						- invalid help param passed`,
				Source:      "Help parser",
				IsRetryable: false,
			})
		}
		commands = append(commands, &types.CommandParameter{
			Name:      val,
			Arguments: nil,
		})
	}
	return commands
}
