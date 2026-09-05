// Package modules holds the stage implementations of the Server Technology Disclosure Analysis test.
// It is used by its own core.go and nothing else.
package modules

import "strings"

// Signature recognises one technology by a substring of a header's value.
type Signature struct {
	Keyword      string
	Technology   string
	VersionToken string
}

// DirectHeader describes a header whose mere presence names a technology, with no substring
// matching involved.
type DirectHeader struct {
	Technology     string
	ValueIsVersion bool
}

// TechnologyDetector recognises the technologies a set of headers discloses.
type TechnologyDetector struct {
	Signatures    map[string][]Signature
	DirectHeaders map[string]DirectHeader
}

// Detect reports every technology a single header discloses, mapped to the version it
// revealed, which is empty when the header names the technology without versioning it.
func (d TechnologyDetector) Detect(headerName string, headerValue string) map[string]string {
	technologies := make(map[string]string)
	name := strings.ToLower(headerName)
	valueLower := strings.ToLower(headerValue)

	for _, signature := range d.Signatures[name] {
		if !strings.Contains(valueLower, signature.Keyword) {
			continue
		}
		version := ""
		if signature.VersionToken != "" {
			version = ExtractVersion(headerValue, signature.VersionToken)
		}
		technologies[signature.Technology] = version
	}

	if direct, present := d.DirectHeaders[name]; present {
		value := ""
		if direct.ValueIsVersion {
			value = headerValue
		}
		technologies[direct.Technology] = value
	}

	return technologies
}

// ExtractVersion attempts to extract version information from HTTP header values using pattern
// recognition for common version formatting conventions.
func ExtractVersion(headerValue, technology string) string {
	valueLower := strings.ToLower(headerValue)
	techLower := strings.ToLower(technology)

	// Find the technology name in the header value
	index := strings.Index(valueLower, techLower)
	if index == -1 {
		return ""
	}

	// Look for version pattern after the technology name
	remaining := headerValue[index+len(techLower):]

	// Common version patterns: /1.2.3, -1.2.3, 1.2.3, v1.2.3
	versionStart := -1
	for i, char := range remaining {
		if char >= '0' && char <= '9' {
			versionStart = i
			break
		}
		if char == '/' || char == '-' || char == 'v' || char == 'V' {
			if i+1 < len(remaining) && remaining[i+1] >= '0' && remaining[i+1] <= '9' {
				versionStart = i + 1
				break
			}
		}
	}

	if versionStart == -1 {
		return ""
	}

	// Extract version string
	versionEnd := versionStart
	for i := versionStart; i < len(remaining); i++ {
		char := remaining[i]
		if (char >= '0' && char <= '9') || char == '.' || char == '-' {
			versionEnd = i + 1
		} else {
			break
		}
	}

	if versionEnd > versionStart {
		return remaining[versionStart:versionEnd]
	}

	return ""
}
