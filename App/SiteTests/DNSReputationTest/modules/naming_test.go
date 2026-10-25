package modules

import "testing"

func TestMatchManagedServiceNeedsSubdomain(t *testing.T) {
	names := Names{ManagedServices: map[string]string{
		"wordpress.com":          "free-hosting",
		"storage.googleapis.com": "free-hosting",
		"googleapis.com":         "other",
	}}
	cases := map[string]string{
		"myblog.wordpress.com":          "wordpress.com",
		"wordpress.com":                 "",
		"bucket.storage.googleapis.com": "storage.googleapis.com",
		"notwordpress.com":              "",
		"a.b.wordpress.com.":            "wordpress.com",
	}
	for host, want := range cases {
		if got, _ := names.MatchManagedService(host); got != want {
			t.Errorf("MatchManagedService(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestDynamicReverseName(t *testing.T) {
	names := Names{DynamicMarkers: []string{"hsd1.", "ftth"}}
	if !names.HasDynamicReverseName([]string{"c-73-1-2-3.hsd1.ma.comcast.net"}) {
		t.Error("Comcast residential name not recognised")
	}
	if names.HasDynamicReverseName([]string{"server1.hosting.example"}) {
		t.Error("hosting name reported as dynamic")
	}
}
