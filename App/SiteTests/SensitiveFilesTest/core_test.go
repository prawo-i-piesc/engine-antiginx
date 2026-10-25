package SensitiveFilesTest

import (
	"Engine-AntiGinx/App/SiteTests"
	"Engine-AntiGinx/App/SiteTests/SensitivePaths"
	"testing"
)

func TestBuildCandidatesCoversSharedList(t *testing.T) {
	if len(candidates) != len(SensitivePaths.Files) {
		t.Fatalf("got %d candidates, want %d (the shared list)", len(candidates), len(SensitivePaths.Files))
	}

	seen := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.Path == "" || candidate.Category == "" {
			t.Errorf("candidate with empty field: %+v", candidate)
		}
		if seen[candidate.Path] {
			t.Errorf("%s appears twice in the shared list", candidate.Path)
		}
		seen[candidate.Path] = true
	}
}

func TestEverySharedCategoryHasASeverity(t *testing.T) {
	for _, file := range SensitivePaths.Files {
		if severityFor(file.Category) == SiteTests.None {
			t.Errorf("category %q (used by %s) maps to no severity", file.Category, file.Path)
		}
	}
}
