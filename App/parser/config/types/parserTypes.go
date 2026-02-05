package types

// CommandParameter represents a parsed command-line parameter with its associated arguments.
// This is the output structure returned by the parser after successful validation.
type CommandParameter struct {
	Name      string   `json:"Name"`      // Parameter name (e.g., "--target", "--tests")
	Arguments []string `json:"Arguments"` // List of validated arguments for this parameter
}

// TestJson represents the root structure of the configuration file.
// It maps directly to the JSON input containing the target URL and a list of parameters.
type TestJson struct {
	Target     string              `json:"Target"`
	Parameters []*CommandParameter `json:"Parameters"`
}

// Parameter defines the specification for a command-line parameter including validation rules.
// It is used internally by the parser to validate user input against expected parameter definitions.

type Parameter struct {
	Arguments   []string // Whitelist of allowed argument values (empty = no restriction)
	DefaultVal  string   // Default value when parameter provided without arguments
	ArgRequired bool     // Whether the parameter must have arguments
	ArgCount    int      // Expected argument count: 1 for single, -1 for multiple
}
