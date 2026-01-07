package parser

// Parser defines the interface for strategies that process user input.
// Any component that translates raw command-line arguments into structured
// application parameters must implement this interface.
type Parser interface {
	// Parse takes a slice of raw string arguments (usually from os.Args)
	// and transforms them into a list of structured CommandParameter objects.
	//
	// It returns a slice of pointers to CommandParameter, ready to be used by the application core.
	// Note: Implementations may panic if the input data violates validation rules.
	Parse(userParameters []string) []*CommandParameter
}
