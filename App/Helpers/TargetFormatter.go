// Package helpers formats target URLs for scan phases.
package helpers

import (
	"Engine-AntiGinx/App/Errors"
	"net/url"
	"strings"
)

// TargetFormatter is responsible for formatting target URLs by intelligently adding appropriate protocol prefixes (http:// or https://) based on the tests being executed.
type TargetFormatter struct{}

// InitializeTargetFormatter creates a new instance of TargetFormatter ready to format target URLs.
func InitializeTargetFormatter() *TargetFormatter {
	return &TargetFormatter{}
}

// Format constructs a properly formatted target URL by adding the appropriate protocol prefix based on the tests being executed.
func (t *TargetFormatter) Format(target string, params []string) *string {
	if strings.HasPrefix(target, "http") || strings.HasPrefix(target, "https") {
		panic(Errors.Error{
			Code: 100,
			Message: `Target Formatter error occurred. This could be due to:
				- invalid target passed to the parameter`,
			Source:      "Target Formatter",
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

// containsParam is a helper function that performs a linear search to determine if a specific test ID (token) exists in the list of tests to be executed.
func (t *TargetFormatter) containsParam(params []string, token string) bool {
	for _, param := range params {
		if param == token {
			return true
		}
	}
	return false
}

// CanonicalURL builds the target URL used by the PreResponse and Structure phases.
func (t *TargetFormatter) CanonicalURL(target string) *url.URL {
	parsed, err := url.Parse("https://" + target)
	if err != nil {
		panic(Errors.Error{
			Code: 101,
			Message: `Target Formatter error occurred. This could be due to:
				- target that cannot be parsed as a URL: ` + err.Error(),
			Source:      "Target Formatter",
			IsRetryable: false,
		})
	}
	return parsed
}
