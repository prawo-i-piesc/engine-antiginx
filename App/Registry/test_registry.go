package Registry

import (
	"Engine-AntiGinx/App/Tests"
	"fmt"
)

var tests = make(map[string]*Tests.ResponseTest)

func init() {
	registerTest(Tests.NewHTTPSTest())
}

func registerTest(t *Tests.ResponseTest) {
	if _, exists := tests[t.Id]; exists {
		panic(fmt.Sprintf("Test with ID %s is already registered", t.Id))
	}
	tests[t.Id] = t
}

func GetTest(testId string) (*Tests.ResponseTest, bool) {
	t, ok := tests[testId]
	return t, ok
}
