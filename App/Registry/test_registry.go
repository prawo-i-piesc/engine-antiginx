package Registry

import (
	error "Engine-AntiGinx/App/Errors"
	"Engine-AntiGinx/App/Tests"
	"fmt"
)

// tests acts as the internal central storage for all registered response tests,
// indexed by their unique string ID.
var tests = make(map[string]*Tests.ResponseTest)

// init automatically registers default tests (like HTTPSTest) when the package is initialized.
// This function runs once before main().
func init() {
	registerTest(Tests.NewHTTPSTest())
	registerTest(Tests.NewHSTSTest())
	registerTest(Tests.NewServerHeaderTest())
}

// registerTest adds a new test instance to the internal registry.
//
// It strictly enforces uniqueness of test IDs. If a test with the same ID
// is already registered, the function triggers a panic with code 100.
// This function is intended for internal use during package initialization.
func registerTest(t *Tests.ResponseTest) {
	if _, exists := tests[t.Id]; exists {
		panic(error.Error{
			Code:    100,
			Message: fmt.Sprintf("Registry error occurred. This could be due to:\n- test with Id %s already exists", t.Id),
			Source:  "Registry",
		})
	}
	tests[t.Id] = t
}

// GetTest retrieves a specific ResponseTest from the registry based on the provided testId.
//
// It acts as a safe lookup method for the internal map.
//
// Returns:
//   - *Tests.ResponseTest: A pointer to the test instance if found.
//   - bool: true if the test exists, false otherwise.
func GetTest(testId string) (*Tests.ResponseTest, bool) {
	t, ok := tests[testId]
	return t, ok
}
