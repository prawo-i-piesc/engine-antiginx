package types

// CommandParameter holds a parsed parameter and its arguments.
type CommandParameter struct {
	Name      string   `json:"Name"`      // Parameter name (e.g., "--target", "--tests")
	Arguments []string `json:"Arguments"` // List of validated arguments for this parameter
}

// TestJson holds a target and parameters from JSON input.
type TestJson struct {
	Target     string              `json:"Target"`
	Parameters []*CommandParameter `json:"Parameters"`
}

// Parameter defines validation rules for a command-line option.

type Parameter struct {
	Arguments   []string // Whitelist of allowed argument values (empty = no restriction)
	DefaultVal  string   // Default value when parameter provided without arguments
	ArgRequired bool     // Whether the parameter must have arguments
	ArgCount    int      // Expected argument count: 1 for single, -1 for multiple
}
