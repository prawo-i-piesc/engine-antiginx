package Runner

import (
	"Engine-AntiGinx/App/Errors"
	"strings"
)

// targetFormatter structure
type targetFormatter struct{}

// InitializeTargetFormatter creates new instance of targetFormatter and returns pointer to it
func InitializeTargetFormatter() *targetFormatter {
	return &targetFormatter{}
}

// Format build target URL based on arguments passed to the test parameter
func (t *targetFormatter) Format(target string, params []string) *string {
	if strings.HasPrefix(target, "http") || strings.HasPrefix(target, "https") {
		panic(Errors.Error{
			Code: 100,
			Message: `Target Validator error occurred. This could be due to:
				- invalid target passed to the parameter`,
			Source:      "Target Validator",
			IsRetryable: false,
		})
	}
	builder := strings.Builder{}
	builder.Grow(len(target) + len("https://"))
	if t.containsParam(params, "https") || t.containsParam(params, "hsts") {
		builder.WriteString("http://")
	} else {
		builder.WriteString("https://")
	}
	builder.WriteString(target)
	target = builder.String()
	return &target
}

// containsParam is a private function which helps to check if token is present in table
func (t *targetFormatter) containsParam(params []string, token string) bool {
	for _, param := range params {
		if param == token {
			return true
		}
	}
	return false
}
