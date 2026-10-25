package DirectoryListingTest

import "testing"

func TestProbesIncludeTargetDirectories(t *testing.T) {
	list := probes("/blog/2026/post.html")

	found := map[string]bool{}
	for _, probe := range list {
		if found[probe.Path] {
			t.Errorf("%s probed twice", probe.Path)
		}
		found[probe.Path] = true
	}
	for _, want := range []string{"/", "/uploads/", "/blog/", "/blog/2026/"} {
		if !found[want] {
			t.Errorf("%s not probed", want)
		}
	}
	if len(list) != len(commonDirectories)+len(sensitiveDirectories)+2 {
		t.Errorf("got %d probes, want the dataset plus 2 target directories", len(list))
	}
}

func TestProbesForRootTarget(t *testing.T) {
	for _, target := range []string{"", "/", "/index.html"} {
		if got := len(probes(target)); got != len(commonDirectories)+len(sensitiveDirectories) {
			t.Errorf("target %q: got %d probes, want only the dataset", target, got)
		}
	}
}
