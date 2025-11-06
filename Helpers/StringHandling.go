package helpers

import "strings"

func ContainsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(strings.ToLower(s), strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
